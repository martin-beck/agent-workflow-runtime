#!/usr/bin/env python3
"""Offline model for the AR-0013 CI and external-observation adapter."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-ci-observation-adapter", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|RQ-[A-Z0-9-]{1,63}|OBS-[A-Z0-9-]{1,63}|EV-[A-Z0-9-]{1,63})$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class ObservationError(ValueError):
    """A fail-closed CI observation adapter violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ObservationError("malformed " + name)
    return value


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ObservationError("invalid " + name)


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(location)
    return errors


def validate_record(record, expected_revision=1, *, expected_task="AR-0013", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0013"):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "request", "local_qualification", "remote_observation", "correlation", "disposition", "evidence"}
    _object(record, fields, "observation record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise ObservationError("unsupported adapter protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or not ID.fullmatch(task["id"]):
        raise ObservationError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise ObservationError("invalid project binding")
    _digest(project["revision"], "project revision")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree:
        raise ObservationError("invalid worktree binding")
    _digest(worktree["digest"], "worktree digest")

    request = _object(record["request"], {"id", "kind", "target_digest", "input_digest", "status"}, "request")
    if not ID.fullmatch(request["id"]) or request["kind"] not in {"hosted_check", "remote_observation"} or request["status"] != "prepared":
        raise ObservationError("invalid or executed request")
    _digest(request["target_digest"], "request target digest")
    _digest(request["input_digest"], "request input digest")

    local = _object(record["local_qualification"], {"status", "result", "evidence_digest"}, "local qualification")
    if local["status"] != "qualified" or local["result"] != "passed":
        raise ObservationError("local qualification is not positive")
    _digest(local["evidence_digest"], "local evidence digest")

    remote = _object(record["remote_observation"], {"status", "verification", "request_id", "target_digest", "evidence_digest"}, "remote observation")
    if remote["status"] != "success" or remote["verification"] != "unverified" or remote["request_id"] != request["id"] or remote["target_digest"] != request["target_digest"]:
        raise ObservationError("unverified or incorrectly correlated remote observation")
    _digest(remote["evidence_digest"], "remote evidence digest")

    correlation = _object(record["correlation"], {"request_id", "target_digest", "observation_digest", "status"}, "correlation")
    if correlation["request_id"] != request["id"] or correlation["target_digest"] != request["target_digest"] or correlation["status"] != "matched":
        raise ObservationError("wrong correlation")
    _digest(correlation["observation_digest"], "observation digest")
    if record["disposition"] != "local_qualified_remote_unverified":
        raise ObservationError("remote observation was promoted to success")

    evidence = record["evidence"]
    if not isinstance(evidence, list) or len(evidence) != 4:
        raise ObservationError("invalid evidence count")
    expected_kinds = {"request", "local_qualification", "remote_observation", "correlation"}
    ids, digests, kinds = set(), set(), set()
    components = {key: record[key] for key in expected_kinds}
    for item in evidence:
        item = _object(item, {"id", "kind", "digest"}, "evidence item")
        if not ID.fullmatch(item["id"]) or item["id"] in ids or item["kind"] in kinds or item["kind"] not in expected_kinds:
            raise ObservationError("replayed or invalid evidence")
        _digest(item["digest"], "evidence digest")
        if item["digest"] in digests or item["digest"] != sha256(canonical_bytes(components[item["kind"]])):
            raise ObservationError("replayed or mismatched evidence digest")
        ids.add(item["id"]); digests.add(item["digest"]); kinds.add(item["kind"])
    if kinds != expected_kinds or _safe(record):
        raise ObservationError("privacy-bearing or incomplete observation record")
    return {"task_revision": expected_revision, "request_id": request["id"], "correlation": "matched", "local": "qualified", "remote": "unverified"}


def project_evidence(record, specification_digest):
    _digest(specification_digest, "specification digest")
    validate_record(record, record["task"]["revision"], expected_task=record["task"]["id"])
    projection = {"protocol": "awr-ci-observation-evidence@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "request": record["request"], "local_qualification": record["local_qualification"], "remote_observation": record["remote_observation"], "correlation": record["correlation"], "disposition": record["disposition"], "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

#!/usr/bin/env python3
"""Deterministic, non-executing AR-0040 publication/release state model."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-publication-release-bridge", "version": "1.0.0"}
CHECKER = "awr-publication-release-checker/1.0.0"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|RV-[A-Z0-9-]{1,63}|CI-[A-Z0-9-]{1,63}|EV-[A-Z0-9-]{1,63}|OP-[A-Z0-9-]{1,63})$")
PRIVATE_KEY = re.compile(r"credential|password|secret|token|prompt|transcript|private|host|raw.?output|email", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class BridgeError(ValueError):
    """A fail-closed AR-0040 contract violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise BridgeError("malformed " + name)
    return value


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise BridgeError("invalid " + name)


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEY.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(location)
    return errors


def validate(record, expected_revision=3, *, expected_task="AR-0040", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0040"):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "artifact", "trace", "result"}
    _object(record, fields, "bridge record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise BridgeError("unsupported bridge protocol")
    if record["task"] != {"id": expected_task, "revision": expected_revision}:
        raise BridgeError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise BridgeError("invalid project binding")
    _digest(project["revision"], "project revision")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree:
        raise BridgeError("invalid worktree binding")
    _digest(worktree["digest"], "worktree digest")
    artifact = _object(record["artifact"], {"branch", "head", "tree", "signature", "dco", "review", "ci"}, "artifact")
    if not isinstance(artifact["branch"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,127}", artifact["branch"]) or ".." in artifact["branch"]:
        raise BridgeError("invalid branch")
    for name in ("head", "tree"):
        if not GIT.fullmatch(artifact[name]):
            raise BridgeError("invalid " + name)
    signature = _object(artifact["signature"], {"status", "algorithm", "key_digest"}, "signature")
    if signature["status"] != "valid" or signature["algorithm"] not in {"ssh", "gpg"}:
        raise BridgeError("invalid signature observation")
    _digest(signature["key_digest"], "signature key digest")
    dco = _object(artifact["dco"], {"status", "trailer_digest"}, "DCO")
    if dco["status"] != "signed":
        raise BridgeError("invalid DCO observation")
    _digest(dco["trailer_digest"], "DCO trailer digest")
    review = _object(artifact["review"], {"id", "status", "target_head", "evidence_digest"}, "review")
    if not ID.fullmatch(review["id"]) or review["status"] != "approved" or review["target_head"] != artifact["head"]:
        raise BridgeError("review is missing or wrong-head")
    _digest(review["evidence_digest"], "review evidence digest")
    ci = _object(artifact["ci"], {"id", "status", "verification", "target_head", "review_id", "evidence_digest"}, "CI")
    if not ID.fullmatch(ci["id"]) or ci["status"] != "success" or ci["verification"] != "unverified" or ci["target_head"] != artifact["head"] or ci["review_id"] != review["id"]:
        raise BridgeError("CI is missing, verified, or wrong-head")
    _digest(ci["evidence_digest"], "CI evidence digest")
    trace = record["trace"]
    if not isinstance(trace, list) or not trace:
        raise BridgeError("missing state trace")
    allowed = {"observed", "qualified", "handoff_ready", "release_ready", "rollback_ready", "interrupted"}
    expected_from, seen = "observed", set()
    for event in trace:
        event = _object(event, {"id", "kind", "from", "to", "head", "evidence_digest"}, "trace event")
        if not ID.fullmatch(event["id"]) or event["id"] in seen or event["from"] != expected_from or event["from"] not in allowed or event["to"] not in allowed:
            raise BridgeError("invalid, replayed, or out-of-order transition")
        if event["head"] != artifact["head"]:
            raise BridgeError("transition crossed exact head")
        _digest(event["evidence_digest"], "transition evidence digest")
        seen.add(event["id"])
        expected_from = event["to"]
    if expected_from != "rollback_ready" or [event["kind"] for event in trace] != ["observe", "qualify", "handoff", "rollback_prepare"]:
        raise BridgeError("trace does not reach rollback_ready through the required states")
    result = _object(record["result"], {"state", "release", "publication", "rollback", "remote_verification", "execute"}, "result")
    if result != {"state": "rollback_ready", "release": "not_performed", "publication": "not_performed", "rollback": "prepared", "remote_verification": "unverified", "execute": False}:
        raise BridgeError("result claims an unperformed operation")
    if _safe(record):
        raise BridgeError("privacy-bearing bridge record")
    return {"task_revision": expected_revision, "state": "rollback_ready", "release": "not_performed", "publication": "not_performed", "remote_verification": "unverified", "execute": False}


def project(record, specification_digest):
    _digest(specification_digest, "specification digest")
    validate(record, record["task"]["revision"], expected_task=record["task"]["id"])
    projection = {"protocol": "awr-publication-release-evidence@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "artifact": record["artifact"], "trace": record["trace"], "result": record["result"], "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

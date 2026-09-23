#!/usr/bin/env python3
"""Offline model for the provider-neutral AR-0012 publication bridge."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-publication-bridge", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT = re.compile(r"^[0-9a-f]{40}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
IDENTIFIER = re.compile(r"^(?:AR-[0-9]{4}|BR-[A-Z0-9-]{1,63}|CM-[A-Z0-9-]{1,63}|RV-[A-Z0-9-]{1,63}|EV-[A-Z0-9-]{1,63}|SES-[A-Z0-9-]{1,63})$")
BRANCH = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class PublicationError(ValueError):
    """A fail-closed publication bridge violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PublicationError("malformed " + name)
    return value


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


def _digest(value, name):
    if not DIGEST.fullmatch(value):
        raise PublicationError("invalid " + name)


def validate_record(record, expected_revision=3, *, expected_task="AR-0012", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0012"):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "branch", "commit", "review", "merge", "publication", "evidence"}
    _object(record, fields, "publication record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise PublicationError("unsupported bridge protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or not TASK.fullmatch(task["id"]):
        raise PublicationError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project or not DIGEST.fullmatch(project["revision"]):
        raise PublicationError("invalid project binding")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise PublicationError("invalid worktree binding")

    branch = _object(record["branch"], {"name", "head"}, "branch")
    if not BRANCH.fullmatch(branch["name"]) or ".." in branch["name"] or not GIT.fullmatch(branch["head"]):
        raise PublicationError("invalid branch observation")
    commit = _object(record["commit"], {"id", "tree", "parents", "exact_head", "signature", "dco"}, "commit")
    if not GIT.fullmatch(commit["id"]) or not GIT.fullmatch(commit["tree"]) or not isinstance(commit["parents"], list) or len(commit["parents"]) > 2 or any(not GIT.fullmatch(parent) for parent in commit["parents"]):
        raise PublicationError("invalid commit observation")
    if commit["exact_head"] is not True:
        raise PublicationError("commit is not exact head")
    signature = _object(commit["signature"], {"status", "algorithm", "key_digest"}, "signature")
    if signature != {"status": "valid", "algorithm": signature["algorithm"], "key_digest": signature["key_digest"]} or signature["status"] != "valid" or signature["algorithm"] not in {"ssh", "gpg"}:
        raise PublicationError("unsigned or invalid commit signature")
    _digest(signature["key_digest"], "signature key digest")
    dco = _object(commit["dco"], {"status", "trailer_digest"}, "DCO")
    if dco["status"] != "signed":
        raise PublicationError("unsigned DCO")
    _digest(dco["trailer_digest"], "DCO trailer digest")
    head = branch["head"]

    review = _object(record["review"], {"id", "status", "target_head", "evidence_digest"}, "review")
    if not IDENTIFIER.fullmatch(review["id"]) or review["status"] != "approved" or review["target_head"] != head:
        raise PublicationError("wrong or incomplete review head")
    _digest(review["evidence_digest"], "review evidence digest")
    merge = _object(record["merge"], {"status", "target_head", "evidence_digest"}, "merge")
    if merge["status"] != "not_performed" or merge["target_head"] != head:
        raise PublicationError("merge is not a non-executing observation")
    _digest(merge["evidence_digest"], "merge evidence digest")
    publication = _object(record["publication"], {"status", "target_head", "evidence_digest"}, "publication")
    if publication["status"] != "not_performed" or publication["target_head"] != head:
        raise PublicationError("publication is not a non-executing observation")
    _digest(publication["evidence_digest"], "publication evidence digest")

    evidence = record["evidence"]
    if not isinstance(evidence, list) or len(evidence) != 5:
        raise PublicationError("invalid evidence count")
    expected_kinds = {"branch", "commit", "review", "merge", "publication"}
    ids, digests, kinds = set(), set(), set()
    components = {key: record[key] for key in expected_kinds}
    for item in evidence:
        item = _object(item, {"id", "kind", "digest"}, "evidence item")
        if not IDENTIFIER.fullmatch(item["id"]) or item["id"] in ids or item["kind"] in kinds or item["kind"] not in expected_kinds:
            raise PublicationError("replayed or invalid evidence")
        _digest(item["digest"], "evidence digest")
        if item["digest"] in digests or item["digest"] != sha256(canonical_bytes(components[item["kind"]])):
            raise PublicationError("replayed or mismatched evidence digest")
        ids.add(item["id"]); digests.add(item["digest"]); kinds.add(item["kind"])
    if kinds != expected_kinds or _safe(record):
        raise PublicationError("privacy-bearing or incomplete publication record")
    return {"task_revision": expected_revision, "head": head, "evidence_count": len(evidence), "merge": "not_performed", "publication": "not_performed"}


def project_evidence(record, specification_digest):
    _digest(specification_digest, "specification digest")
    validate_record(record, record["task"]["revision"], expected_task=record["task"]["id"])
    projection = {"protocol": "awr-publication-evidence@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "branch": record["branch"], "commit": {"id": record["commit"]["id"], "tree": record["commit"]["tree"], "exact_head": True, "signature": record["commit"]["signature"], "dco": record["commit"]["dco"]}, "review": record["review"], "merge": record["merge"], "publication": record["publication"], "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

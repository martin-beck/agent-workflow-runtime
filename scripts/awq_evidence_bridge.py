#!/usr/bin/env python3
"""Offline standard-library model for the AR-0009 AWQ evidence bridge."""

import hashlib
import json
import re

BRIDGE_PROTOCOL = {"id": "awr-awq-evidence", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|BR-[A-Z0-9-]{1,63}|OBS-[A-Z0-9-]{1,63}|SES-[A-Z0-9-]{1,63})$")
HEX = re.compile(r"^[0-9a-f]{40}$")
CATEGORIES = {"test", "formal", "resource", "privacy", "provenance", "lifecycle"}
RESULTS = {"passed", "failed", "blocked", "skipped", "not_run"}
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data)", re.I)


class BridgeError(ValueError):
    """A fail-closed bridge violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise BridgeError("malformed " + name)
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
    elif isinstance(value, str) and PRIVATE.search(value):
        errors.append(location)
    return errors


def validate_bridge(record, expected_revision, *, expected_task="AR-0009", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0009"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "observations"}
    _object(record, top, "bridge record")
    if record["schema_version"] != 1 or record["protocol"] != BRIDGE_PROTOCOL:
        raise BridgeError("unsupported bridge protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or not ID.fullmatch(task["id"]):
        raise BridgeError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    session = _object(record["session"], {"id"}, "session")
    if project["key"] != expected_project or not HEX.fullmatch(project["revision"]):
        raise BridgeError("invalid project binding")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise BridgeError("invalid worktree binding")
    if not ID.fullmatch(session["id"]):
        raise BridgeError("invalid session binding")
    observations = record["observations"]
    if not isinstance(observations, list) or not observations or len(observations) > 64:
        raise BridgeError("invalid observation count")
    ids, digests = set(), set()
    for sequence, observation in enumerate(observations, 1):
        _object(observation, {"id", "sequence", "category", "result", "evidence_digest"}, "observation")
        if observation["sequence"] != sequence or not isinstance(observation["sequence"], int) or isinstance(observation["sequence"], bool):
            raise BridgeError("invalid observation sequence")
        if not ID.fullmatch(observation["id"]) or observation["id"] in ids:
            raise BridgeError("duplicate or invalid observation id")
        if observation["category"] not in CATEGORIES or observation["result"] not in RESULTS or not DIGEST.fullmatch(observation["evidence_digest"]):
            raise BridgeError("invalid observation values")
        if observation["evidence_digest"] in digests:
            raise BridgeError("replayed evidence digest")
        ids.add(observation["id"]); digests.add(observation["evidence_digest"])
    if _safe(record):
        raise BridgeError("privacy-bearing bridge record")
    return {"observations": len(observations), "task_revision": expected_revision, "session_id": session["id"], "last_sequence": len(observations)}


def project_evidence(record, specification_digest):
    if not DIGEST.fullmatch(specification_digest):
        raise BridgeError("invalid specification digest")
    validate_bridge(record, record["task"]["revision"], expected_task=record["task"]["id"])
    items = [{"id": item["id"], "sequence": item["sequence"], "category": item["category"], "result": item["result"], "evidence_digest": item["evidence_digest"]} for item in record["observations"]]
    projection = {"protocol": "awr-awq-evidence@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"], "quality_status": "not_decided", "observations": items, "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

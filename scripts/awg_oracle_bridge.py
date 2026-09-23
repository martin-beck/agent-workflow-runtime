#!/usr/bin/env python3
"""Offline provider-neutral AWG oracle discussion admission model for AR-0010."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-awg-oracle-bridge", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|OBS-[A-Z0-9-]{1,63}|ALT-[A-Z0-9-]{1,63}|SES-[A-Z0-9-]{1,63})$")
HEX = re.compile(r"^[0-9a-f]{40}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data)", re.I)
INJECTED = re.compile(r"(?:accepted|approved|rejected|selected|winner|quality.?status|decision)", re.I)
CATEGORIES = {"lifecycle", "test", "resource", "failure", "provenance"}
RESULTS = {"passed", "failed", "blocked", "skipped", "not_run"}
UNCERTAINTY = {"low", "medium", "high"}
FACTORS = {"complete_observation", "incomplete_observation", "conflicting_observation", "stale_risk"}


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
            if PRIVATE.search(str(key)) or INJECTED.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE.search(value):
        errors.append(location)
    return errors


def validate_bridge(record, expected_revision=3, *, expected_task="AR-0010", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0010", expected_session="SES-AR0010-REFERENCE"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "observations", "uncertainty", "alternatives", "confidence"}
    _object(record, top, "bridge record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
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
    if session["id"] != expected_session or not ID.fullmatch(session["id"]):
        raise BridgeError("invalid session binding")

    observations = record["observations"]
    if not isinstance(observations, list) or not observations or len(observations) > 32:
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

    uncertainty = _object(record["uncertainty"], {"level", "factors"}, "uncertainty")
    if uncertainty["level"] not in UNCERTAINTY or not isinstance(uncertainty["factors"], list) or not 1 <= len(uncertainty["factors"]) <= 4:
        raise BridgeError("invalid uncertainty")
    if any(factor not in FACTORS for factor in uncertainty["factors"]) or len(set(uncertainty["factors"])) != len(uncertainty["factors"]):
        raise BridgeError("invalid uncertainty factor")

    alternatives = record["alternatives"]
    if not isinstance(alternatives, list) or not 1 <= len(alternatives) <= 4:
        raise BridgeError("invalid alternative count")
    alternative_ids, alternative_digests = set(), set(digests)
    for alternative in alternatives:
        _object(alternative, {"id", "evidence_digest", "confidence"}, "alternative")
        if not ID.fullmatch(alternative["id"]) or not alternative["id"].startswith("ALT-") or alternative["id"] in alternative_ids:
            raise BridgeError("duplicate or invalid alternative id")
        if not DIGEST.fullmatch(alternative["evidence_digest"]) or alternative["evidence_digest"] in alternative_digests:
            raise BridgeError("invalid alternative digest")
        if not isinstance(alternative["confidence"], int) or isinstance(alternative["confidence"], bool) or not 0 <= alternative["confidence"] <= 100:
            raise BridgeError("invalid alternative confidence")
        alternative_ids.add(alternative["id"]); alternative_digests.add(alternative["evidence_digest"])

    confidence = _object(record["confidence"], {"level", "score"}, "confidence")
    if confidence["level"] not in UNCERTAINTY or not isinstance(confidence["score"], int) or isinstance(confidence["score"], bool) or not 0 <= confidence["score"] <= 100:
        raise BridgeError("invalid confidence")
    if _safe(record):
        raise BridgeError("private or decision-bearing bridge record")
    return {"observations": len(observations), "alternatives": len(alternatives), "task_revision": expected_revision, "session_id": session["id"]}


def project_admission(record, specification_digest):
    if not DIGEST.fullmatch(specification_digest):
        raise BridgeError("invalid specification digest")
    validate_bridge(record, record["task"]["revision"], expected_task=record["task"]["id"], expected_session=record["session"]["id"])
    projection = {
        "protocol": "awr-awg-oracle-admission@1.0.0",
        "kind": "discussion_admission",
        "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"],
        "observations": record["observations"], "uncertainty": record["uncertainty"], "alternatives": record["alternatives"], "confidence": record["confidence"],
        "admission_status": "not_decided", "specification_digest": specification_digest,
    }
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

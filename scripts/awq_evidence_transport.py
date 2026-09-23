#!/usr/bin/env python3
"""Deterministic, offline model of the AR-0052 AWQ evidence transport.

The fake AWQ service is deliberately local.  This module validates the
transport contract and projects an AWQ observation; it never submits evidence
to AWQ, contacts a provider, or mutates Coordinator state.
"""

import hashlib
import json
import re
from copy import deepcopy

PROTOCOL = {"id": "awr-awq-evidence-transport", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR|EVID|OP|SES|GATE|ACK)-[A-Z0-9-]{1,63}$")
PRIVATE = re.compile(
    r"(?:credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|raw.?output|authorization|cookie)", re.I
)


class TransportError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_safe(v) for v in value)
    return isinstance(value, str) and bool(PRIVATE.search(value))


def _fields(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise TransportError("malformed " + name)
    return value


def _binding(record):
    return {key: record[key] for key in ("task", "project", "worktree", "session")}


def validate_record(record, expected_revision=5):
    _fields(record, {"protocol", "task", "project", "worktree", "session", "evidence", "submission", "gate"}, "record")
    if record["protocol"] != PROTOCOL:
        raise TransportError("unsupported protocol")
    task = _fields(record["task"], {"id", "revision"}, "task")
    if task != {"id": "AR-0052", "revision": expected_revision}:
        raise TransportError("stale task revision")
    project = _fields(record["project"], {"key", "revision"}, "project")
    worktree = _fields(record["worktree"], {"key", "digest"}, "worktree")
    session = _fields(record["session"], {"id"}, "session")
    if project["key"] != "agent-workflow-runtime" or not DIGEST.fullmatch(project["revision"]):
        raise TransportError("invalid project binding")
    if worktree["key"] != "agent-workflow-runtime-0052" or not DIGEST.fullmatch(worktree["digest"]):
        raise TransportError("invalid worktree binding")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]):
        raise TransportError("invalid session binding")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or not evidence or len(evidence) > 64:
        raise TransportError("invalid evidence batch")
    ids, digests = set(), set()
    for sequence, item in enumerate(evidence, 1):
        _fields(item, {"id", "sequence", "kind", "outcome", "evidence_digest"}, "evidence")
        if item["sequence"] != sequence or not re.fullmatch(r"EVID-[A-Z0-9-]{1,63}", item["id"]):
            raise TransportError("invalid evidence sequence")
        if item["id"] in ids or item["evidence_digest"] in digests or not DIGEST.fullmatch(item["evidence_digest"]):
            raise TransportError("duplicate evidence")
        if item["kind"] not in {"test", "formal", "provenance", "privacy"} or item["outcome"] not in {"passed", "failed", "blocked"}:
            raise TransportError("invalid evidence value")
        ids.add(item["id"]); digests.add(item["evidence_digest"])
    submission = _fields(record["submission"], {"operation_id", "attempt", "max_attempts", "state", "network", "acknowledged", "interrupted", "evidence_digests"}, "submission")
    if not re.fullmatch(r"OP-[A-Z0-9-]{1,63}", submission["operation_id"]):
        raise TransportError("invalid operation")
    if submission["attempt"] not in (1, 2, 3) or submission["max_attempts"] not in (1, 2, 3) or submission["attempt"] > submission["max_attempts"]:
        raise TransportError("invalid retry bound")
    if submission["state"] not in {"accepted", "rejected", "blocked", "unknown_outcome"}:
        raise TransportError("invalid transport state")
    if submission["network"] != "not_performed" or not isinstance(submission["acknowledged"], bool) or not isinstance(submission["interrupted"], bool):
        raise TransportError("unsafe transport observation")
    if submission["evidence_digests"] != [item["evidence_digest"] for item in evidence]:
        raise TransportError("evidence correlation mismatch")
    gate = _fields(record["gate"], {"id", "authority", "status", "decision_digest", "ack_id", "binding_digest"}, "gate")
    if not re.fullmatch(r"GATE-[A-Z0-9-]{1,63}", gate["id"]) or gate["authority"] != "awq" or gate["status"] not in {"accepted", "rejected", "blocked", "unknown_outcome"}:
        raise TransportError("invalid gate observation")
    if gate["binding_digest"] != digest(_binding(record)) or not DIGEST.fullmatch(gate["decision_digest"]):
        raise TransportError("gate binding mismatch")
    if gate["status"] == "accepted" and submission["acknowledged"] is not True:
        raise TransportError("accepted evidence lacks acknowledgement")
    if gate["status"] == "unknown_outcome" and submission["acknowledged"]:
        raise TransportError("unknown outcome acknowledged as success")
    if gate["status"] in {"rejected", "blocked", "unknown_outcome"} and gate["ack_id"] is not None:
        raise TransportError("non-acceptance acknowledgement")
    if gate["status"] == "accepted" and not re.fullmatch(r"ACK-[A-Z0-9-]{1,63}", gate["ack_id"] or ""):
        raise TransportError("missing AWQ acknowledgement")
    if _safe(record):
        raise TransportError("privacy-bearing transport")
    return {"task_revision": expected_revision, "evidence_count": len(evidence), "status": gate["status"], "live_verification": "unverified"}


def project(record):
    validate_record(record, record["task"]["revision"])
    projection = {"protocol": "awr-awq-evidence-transport@1.0.0", "binding": _binding(record), "evidence_digests": record["submission"]["evidence_digests"], "gate": {"authority": "awq", "status": record["gate"]["status"], "decision_digest": record["gate"]["decision_digest"]}, "quality_status": "not_decided_by_runtime", "network": "not_performed"}
    projection["projection_digest"] = digest(projection)
    return projection


class LocalAWQFake:
    """An authority-shaped local fake used only for deterministic replay tests."""
    def __init__(self, binding, responses):
        self.binding = deepcopy(binding)
        self.responses = list(responses)
        self.operations = {}

    def submit(self, request):
        if request["binding"] != self.binding:
            raise TransportError("crossed binding")
        fingerprint = digest({key: value for key, value in request.items() if key != "attempt"})
        prior = self.operations.get(request["operation_id"])
        if prior:
            if prior[0] != fingerprint:
                raise TransportError("changed replay")
            return deepcopy(prior[1])
        response = self.responses.pop(0) if self.responses else {"status": "unknown_outcome"}
        if response["status"] == "unknown_outcome":
            return {"status": "unknown_outcome", "ack_id": None}
        if response["status"] not in {"accepted", "rejected", "blocked"}:
            raise TransportError("ambiguous AWQ response")
        result = {"status": response["status"], "ack_id": response.get("ack_id")}
        self.operations[request["operation_id"]] = (fingerprint, result)
        return deepcopy(result)

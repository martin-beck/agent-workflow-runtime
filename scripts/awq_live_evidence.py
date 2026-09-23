#!/usr/bin/env python3
"""Offline model for the AR-0037 AWQ live-evidence boundary.

This module validates and projects supplied envelopes.  It never opens a
transport, reads credentials, contacts AWQ, or mutates Coordinator state.
"""

import hashlib
import json
import re


PROTOCOL = {"id": "awr-awq-live-evidence", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^(?:AR|EVID|OP|EVT|CHK|GATE|SES)-[A-Z0-9-]{1,63}$")
VERSION = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
PRIVATE = re.compile(
    r"(?:credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|raw.?output|personal.?data|authorization|cookie)", re.I
)
EVIDENCE_CATEGORIES = {"test", "formal", "resource", "privacy", "provenance", "lifecycle"}
EVIDENCE_RESULTS = {"passed", "failed", "blocked", "skipped", "not_run"}
EVENTS = {"prepare", "checkpoint", "interrupt", "resume"}
GATE_STATUSES = {"accepted", "rejected", "blocked", "not_decided"}


class EvidenceError(ValueError):
    """A fail-closed contract violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise EvidenceError("malformed " + name)
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


def _binding(record):
    return {key: record[key] for key in ("task", "project", "worktree", "session")}


def validate(record, expected_revision=1, *, expected_task="AR-0037", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0037"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "tool_versions", "evidence", "transport", "gate_observation"}
    _object(record, top, "evidence record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise EvidenceError("unsupported evidence protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or not ID.fullmatch(task["id"]):
        raise EvidenceError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    session = _object(record["session"], {"id"}, "session")
    if project["key"] != expected_project or not HEX.fullmatch(project["revision"]):
        raise EvidenceError("invalid project binding")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise EvidenceError("invalid worktree binding")
    if not ID.fullmatch(session["id"]):
        raise EvidenceError("invalid session binding")

    tools = record["tool_versions"]
    if not isinstance(tools, list) or not tools or len(tools) > 16:
        raise EvidenceError("invalid tool version list")
    tool_ids = set()
    for tool in tools:
        _object(tool, {"id", "version"}, "tool version")
        if not ID.fullmatch(tool["id"]) or tool["id"] in tool_ids or not VERSION.fullmatch(tool["version"]):
            raise EvidenceError("invalid tool version")
        tool_ids.add(tool["id"])

    evidence = record["evidence"]
    if not isinstance(evidence, list) or not evidence or len(evidence) > 64:
        raise EvidenceError("invalid evidence count")
    evidence_ids, evidence_digests = set(), set()
    for sequence, item in enumerate(evidence, 1):
        _object(item, {"id", "sequence", "category", "result", "qualification", "evidence_digest"}, "evidence item")
        if item["sequence"] != sequence or not isinstance(item["sequence"], int) or isinstance(item["sequence"], bool):
            raise EvidenceError("invalid evidence sequence")
        if not ID.fullmatch(item["id"]) or not item["id"].startswith("EVID-") or item["id"] in evidence_ids:
            raise EvidenceError("duplicate or invalid evidence id")
        if item["category"] not in EVIDENCE_CATEGORIES or item["result"] not in EVIDENCE_RESULTS or item["qualification"] not in {"offline", "live"}:
            raise EvidenceError("invalid evidence value")
        if not DIGEST.fullmatch(item["evidence_digest"]) or item["evidence_digest"] in evidence_digests:
            raise EvidenceError("replayed evidence digest")
        evidence_ids.add(item["id"]); evidence_digests.add(item["evidence_digest"])

    transport = _object(record["transport"], {"operation_id", "attempt", "state", "network", "auth_state", "approval", "events"}, "transport")
    if not ID.fullmatch(transport["operation_id"]) or not transport["operation_id"].startswith("OP-") or transport["attempt"] != 1 or transport["state"] != "recovered":
        raise EvidenceError("invalid transport state")
    if transport["network"] != "not_performed" or transport["auth_state"] != "not_supplied" or transport["approval"] != "not_granted":
        raise EvidenceError("live transport is not fail-closed")
    events = transport["events"]
    if not isinstance(events, list) or len(events) != 4:
        raise EvidenceError("invalid transport event count")
    seen_events = set()
    for sequence, event in enumerate(events, 1):
        _object(event, {"id", "sequence", "kind"}, "transport event")
        if event["sequence"] != sequence or not isinstance(event["sequence"], int) or event["id"] in seen_events or not ID.fullmatch(event["id"]):
            raise EvidenceError("invalid transport event")
        if event["kind"] != ("prepare", "checkpoint", "interrupt", "resume")[sequence - 1]:
            raise EvidenceError("invalid interruption or recovery order")
        seen_events.add(event["id"])

    gate = _object(record["gate_observation"], {"id", "authority", "status", "binding_digest", "evidence_digests", "decision_source", "gate_digest"}, "gate observation")
    if not ID.fullmatch(gate["id"]) or not gate["id"].startswith("GATE-") or gate["authority"] != "awq" or gate["status"] not in GATE_STATUSES or gate["decision_source"] != "external_observation":
        raise EvidenceError("unauthorized or invalid gate observation")
    if gate["binding_digest"] != sha256(canonical_bytes(_binding(record))):
        raise EvidenceError("gate binding digest mismatch")
    if gate["evidence_digests"] != [item["evidence_digest"] for item in evidence]:
        raise EvidenceError("gate evidence correlation mismatch")
    unsigned_gate = dict(gate); unsigned_gate.pop("gate_digest")
    if not DIGEST.fullmatch(gate["gate_digest"]) or gate["gate_digest"] != sha256(canonical_bytes(unsigned_gate)):
        raise EvidenceError("gate digest mismatch")
    if _safe(record):
        raise EvidenceError("privacy-bearing evidence envelope")
    return {"evidence": len(evidence), "task_revision": expected_revision, "session_id": session["id"], "transport_state": transport["state"], "gate_status": gate["status"]}


def project(record, specification_digest):
    if not DIGEST.fullmatch(specification_digest):
        raise EvidenceError("invalid specification digest")
    validate(record, record["task"]["revision"], expected_task=record["task"]["id"], expected_project=record["project"]["key"], expected_worktree=record["worktree"]["key"])
    gate = record["gate_observation"]
    projection = {
        "protocol": "awr-awq-live-evidence@1.0.0",
        "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"],
        "tool_versions": record["tool_versions"],
        "evidence": record["evidence"],
        "transport": {"operation_id": record["transport"]["operation_id"], "state": record["transport"]["state"], "network": "not_performed"},
        "gate_consumption": {"authority": "awq", "status": "observed", "decision": gate["status"], "gate_digest": gate["gate_digest"]},
        "quality_status": "not_decided_by_runtime",
        "specification_digest": specification_digest,
    }
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection


class OfflineHarness:
    """Deterministic fixture harness; no operation in this class is live."""

    def __init__(self, specification, record):
        self.specification = specification
        self.record = record

    def qualify(self, expected_revision=1):
        result = validate(self.record, expected_revision)
        digest = sha256(canonical_bytes(self.specification))
        return {**result, "specification_digest": digest, "projection": project(self.record, digest), "live_verification": "unverified"}

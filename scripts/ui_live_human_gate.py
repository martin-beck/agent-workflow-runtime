#!/usr/bin/env python3
"""Offline AR-0039 UI session and human-gate model."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-ui-live-human-gate", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PROJECT = re.compile(r"^[0-9a-f]{40}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
OPAQUE = re.compile(r"^(?:AR|ALT|EVT|GATE|LSE|REQ|SES|UI|WRK)-[A-Z0-9-]{1,63}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|cookie|authorization)", re.I)
DECISION = re.compile(r"(?:approved|rejected|winner|selected|guidance|recommendation|awg.?decision|awq.?accept)", re.I)


class GateError(ValueError):
    """A fail-closed AR-0039 contract violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise GateError("malformed " + name)
    return value


def _scan(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                errors.append(location + "." + str(key))
            _scan(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and (PRIVATE.search(value) or (DECISION.search(value) and value not in {"validated_input_pending_authority", "not_decided"})):
        errors.append(location)
    return errors


def binding(record):
    return {key: record[key] for key in ("task", "project", "worktree", "session", "lease")}


def binding_digest(record):
    return sha256(canonical_bytes(binding(record)))


def trace_digest(record):
    return sha256(canonical_bytes({"events": record["events"], "final_event": record["final_event"]}))


def decision_digest(record):
    decision = record["human_gate"]
    return sha256(canonical_bytes({"request_id": decision["request_id"], "attempt": 1, "selection_id": decision["selection_id"], "input_event_id": decision["input_event_id"], "validation": "ui_validated"}))


def _event(event, sequence, ids, digests):
    common = {"event_id", "sequence", "event_type", "disposition", "evidence_digest"}
    if event.get("event_type") == "input_validated":
        common |= {"request_id", "selection_id", "validation"}
    _object(event, common, "event")
    if event["sequence"] != sequence or not isinstance(event["sequence"], int) or isinstance(event["sequence"], bool):
        raise GateError("invalid event sequence")
    if not OPAQUE.fullmatch(str(event["event_id"])) or not DIGEST.fullmatch(str(event["evidence_digest"])):
        raise GateError("invalid event identity or digest")
    if event["event_id"] in ids or event["evidence_digest"] in digests:
        raise GateError("replayed event material")
    allowed = {"session_opened": "prepared", "gate_rendered": "rendered", "input_validated": "validated_input", "ui_checkpointed": "checkpointed"}
    if event["event_type"] not in allowed or event["disposition"] != allowed[event["event_type"]]:
        raise GateError("invalid event transition")
    if event["event_type"] == "input_validated":
        if not OPAQUE.fullmatch(event["request_id"]) or not OPAQUE.fullmatch(event["selection_id"]):
            raise GateError("invalid human-gate identity")
        if event["validation"] != "ui_validated":
            raise GateError("input is not UI-validated")
    ids.add(event["event_id"]); digests.add(event["evidence_digest"])


def validate(record, expected_revision=3, *, expected_task="AR-0039", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0039"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "lease", "tool_versions", "request", "human_gate", "events", "final_event", "resume"}
    _object(record, top, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise GateError("unsupported protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision}:
        raise GateError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    session = _object(record["session"], {"id"}, "session")
    lease = _object(record["lease"], {"id", "worker_id", "digest"}, "lease")
    if project["key"] != expected_project or not PROJECT.fullmatch(project["revision"]):
        raise GateError("invalid project binding")
    if worktree["key"] != expected_worktree or not WORKTREE.fullmatch(worktree["key"]) or not DIGEST.fullmatch(worktree["digest"]):
        raise GateError("invalid worktree binding")
    if not OPAQUE.fullmatch(session["id"]) or not session["id"].startswith("SES-"):
        raise GateError("invalid session binding")
    if not OPAQUE.fullmatch(lease["id"]) or not lease["id"].startswith("LSE-") or not OPAQUE.fullmatch(lease["worker_id"]) or not lease["worker_id"].startswith("WRK-") or not DIGEST.fullmatch(lease["digest"]):
        raise GateError("invalid lease binding")
    tools = record["tool_versions"]
    if not isinstance(tools, list) or not tools or len(tools) > 8:
        raise GateError("invalid tool versions")
    for tool in tools:
        _object(tool, {"id", "version"}, "tool")
        if not OPAQUE.fullmatch(tool["id"]):
            raise GateError("invalid tool identity")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", tool["version"]):
            raise GateError("invalid tool version")
    request = _object(record["request"], {"id", "attempt", "context_digest"}, "request")
    if not OPAQUE.fullmatch(request["id"]) or not request["id"].startswith("REQ-") or request["attempt"] != 1 or not DIGEST.fullmatch(request["context_digest"]):
        raise GateError("invalid request")
    gate = _object(record["human_gate"], {"request_id", "attempt", "input_event_id", "selection_id", "status", "authority", "quality_status", "guidance_status", "binding_digest", "input_digest"}, "human gate")
    if gate["request_id"] != request["id"] or gate["attempt"] != 1 or not OPAQUE.fullmatch(gate["input_event_id"]) or not OPAQUE.fullmatch(gate["selection_id"]) or gate["status"] != "validated_input_pending_authority" or gate["authority"] != "ui" or gate["quality_status"] != "not_decided" or gate["guidance_status"] != "not_decided" or not DIGEST.fullmatch(gate["input_digest"]) or gate["binding_digest"] != binding_digest(record):
        raise GateError("invalid human-gate binding")
    events = record["events"]
    if not isinstance(events, list) or len(events) != 4 or events[0]["event_type"] != "session_opened":
        raise GateError("invalid event trace")
    ids, digests = set(), set()
    for sequence, event in enumerate(events, 1):
        _event(event, sequence, ids, digests)
    input_event = next(event for event in events if event["event_type"] == "input_validated")
    if input_event["event_id"] != gate["input_event_id"] or input_event["request_id"] != request["id"] or input_event["selection_id"] != gate["selection_id"]:
        raise GateError("input is not bound to the gate")
    if gate["input_digest"] != sha256(canonical_bytes({"request_id": request["id"], "attempt": 1, "selection_id": gate["selection_id"], "input_event_id": gate["input_event_id"], "validation": "ui_validated"})) or decision_digest(record) != record["human_gate"]["input_digest"]:
        raise GateError("human input digest mismatch")
    final = _object(record["final_event"], {"event_id", "sequence", "event_type", "disposition", "reason", "evidence_digest"}, "final event")
    if final["sequence"] != 5 or final["event_type"] != "safe_exit" or final["disposition"] != "safe_exit" or final["reason"] != "user_requested" or final["event_id"] in ids or not OPAQUE.fullmatch(final["event_id"]) or not DIGEST.fullmatch(final["evidence_digest"]):
        raise GateError("invalid safe exit")
    resume = _object(record["resume"], {"status", "checkpoint_event_id", "prior_trace_digest", "binding_digest"}, "resume")
    if resume["status"] != "resumable" or resume["checkpoint_event_id"] not in ids or not any(event["event_id"] == resume["checkpoint_event_id"] and event["event_type"] == "ui_checkpointed" for event in events) or resume["prior_trace_digest"] != trace_digest(record) or resume["binding_digest"] != binding_digest(record):
        raise GateError("invalid resumable safe exit")
    if _scan(record):
        raise GateError("private or authority-bearing value")
    return {"protocol": "awr-ui-live-human-gate@1.0.0", "task_revision": expected_revision, "session_id": session["id"], "events": 5, "final": "safe_exit", "status": gate["status"], "resumable": True}


def project(record, specification_digest):
    validate(record, record["task"]["revision"], expected_task=record["task"]["id"], expected_project=record["project"]["key"], expected_worktree=record["worktree"]["key"])
    if not DIGEST.fullmatch(specification_digest):
        raise GateError("invalid specification digest")
    projection = {"protocol": "awr-ui-live-human-gate@1.0.0", "visibility": "private_revision_bound", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"], "lease": record["lease"], "request": record["request"], "events": [{"event_id": event["event_id"], "sequence": event["sequence"], "event_type": event["event_type"], "evidence_digest": event["evidence_digest"]} for event in record["events"]], "human_gate": {"request_id": record["human_gate"]["request_id"], "input_event_id": record["human_gate"]["input_event_id"], "input_digest": record["human_gate"]["input_digest"], "status": "validated_input_pending_authority", "quality_status": "not_decided", "guidance_status": "not_decided"}, "safe_exit": "resumable", "live_verification": "unverified", "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

#!/usr/bin/env python3
"""Offline production-shaped UI human-gate session bridge for AR-0054."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-production-ui-human-gate", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OPAQUE = re.compile(r"^(?:AR|DEC|EVT|GATE|LSE|OP|REQ|SES|UI|WRK)-[A-Z0-9-]{1,63}$")
PROJECT = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|cookie|authorization)", re.I)
DECISIONS = {"approve", "reject", "clarify", "timeout", "cancel"}


class SessionError(ValueError):
    """A fail-closed production UI session violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()


def _object(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise SessionError("malformed " + name)
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
    elif isinstance(value, str) and PRIVATE.search(value):
        errors.append(location)
    return errors


def binding(record):
    return {key: record[key] for key in ("task", "project", "worktree", "session")}


def binding_digest(record):
    return sha256(binding(record))


def input_digest(record):
    request = record["request"]
    return sha256({"request_id": request["id"], "attempt": request["attempt"], "options": request["options"], "context_digest": request["context_digest"]})


def final_digest(final_event):
    return sha256({key: final_event[key] for key in ("event_id", "sequence", "event_type", "decision", "reason", "request_id", "input_event_id", "evidence_digest")})


def create_session(binding_record, request, *, session_id="SES-AR0054", expires_at=120):
    """Create only a private, digest-bound session description; no file is opened."""
    if expires_at <= 0 or not OPAQUE.fullmatch(session_id):
        raise SessionError("invalid session creation input")
    record = {
        "schema_version": 1, "protocol": PROTOCOL,
        **binding_record,
        "session": {"id": session_id, "generation": 1, "replacement_of": None},
        "private_session": {"visibility": "private_revision_bound", "file_mode": "0600", "storage": "caller_supplied_file", "expires_at": expires_at, "state": "created"},
        "request": request,
    }
    record["private_session"]["binding_digest"] = binding_digest(record)
    return record


def rendering_inputs(record):
    """Return bounded UI inputs without prompts, transcripts, paths, or secrets."""
    validate(record, record["task"]["revision"], require_terminal=False)
    return {"request_id": record["request"]["id"], "attempt": record["request"]["attempt"], "options": record["request"]["options"], "input_digest": input_digest(record), "expires_at": record["private_session"]["expires_at"]}


def _validate_binding(record, revision, expected_task="AR-0054", expected_worktree="agent-workflow-runtime-0054"):
    task = _object(record["task"], {"id", "revision"}, "task")
    project = _object(record["project"], {"key", "revision"}, "project")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    session = _object(record["session"], {"id", "generation", "replacement_of"}, "session")
    if task != {"id": expected_task, "revision": revision} or not OPAQUE.fullmatch(task["id"]):
        raise SessionError("stale task revision")
    if project["key"] != "agent-workflow-runtime" or not PROJECT.fullmatch(project["revision"]):
        raise SessionError("invalid project binding")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise SessionError("invalid worktree binding")
    if not OPAQUE.fullmatch(session["id"]) or not session["id"].startswith("SES-") or session["generation"] != 1 or session["replacement_of"] is not None:
        raise SessionError("invalid or replaced session")


def _event(event, sequence, ids, digests):
    fields = {"event_id", "sequence", "event_type", "disposition", "evidence_digest"}
    if event.get("event_type") == "input_validated":
        fields |= {"request_id", "decision", "input_event_id", "human_present", "validation"}
    _object(event, fields, "event")
    if event["sequence"] != sequence or type(event["sequence"]) is not int or not OPAQUE.fullmatch(str(event["event_id"])) or not DIGEST.fullmatch(str(event["evidence_digest"])):
        raise SessionError("invalid event identity or sequence")
    if event["event_id"] in ids or event["evidence_digest"] in digests:
        raise SessionError("duplicate event")
    expected = {"session_created": "created", "gate_rendered": "rendered", "input_validated": "validated", "ui_checkpointed": "checkpointed"}
    if event["event_type"] not in expected or event["disposition"] != expected[event["event_type"]]:
        raise SessionError("invalid event transition")
    if event["event_type"] == "input_validated":
        if event["decision"] not in DECISIONS or type(event["human_present"]) is not bool or (event["decision"] != "timeout" and event["human_present"] is not True) or event["validation"] != "ui_validated" or not OPAQUE.fullmatch(event["request_id"]) or not OPAQUE.fullmatch(event["input_event_id"]):
            raise SessionError("missing validated human input")
    ids.add(event["event_id"]); digests.add(event["evidence_digest"])


def validate(record, expected_revision=5, *, require_terminal=True, expected_task="AR-0054", expected_worktree="agent-workflow-runtime-0054"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "private_session", "request", "render", "events", "final_event", "persistence"}
    _object(record, top, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise SessionError("unsupported protocol")
    _validate_binding(record, expected_revision, expected_task, expected_worktree)
    private = _object(record["private_session"], {"visibility", "file_mode", "storage", "expires_at", "state", "binding_digest"}, "private session")
    if private["visibility"] != "private_revision_bound" or private["file_mode"] != "0600" or private["storage"] != "caller_supplied_file" or type(private["expires_at"]) is not int or private["expires_at"] <= 0 or private["binding_digest"] != binding_digest(record):
        raise SessionError("invalid private session")
    request = _object(record["request"], {"id", "attempt", "context_digest", "options"}, "request")
    if not OPAQUE.fullmatch(request["id"]) or not request["id"].startswith("REQ-") or request["attempt"] != 1 or not DIGEST.fullmatch(request["context_digest"]) or not isinstance(request["options"], list) or not 1 <= len(request["options"]) <= 8:
        raise SessionError("invalid gate request")
    option_ids = set()
    for option in request["options"]:
        _object(option, {"id", "evidence_digest"}, "option")
        if not OPAQUE.fullmatch(option["id"]) or option["id"] in option_ids or not DIGEST.fullmatch(option["evidence_digest"]):
            raise SessionError("invalid gate option")
        option_ids.add(option["id"])
    render = _object(record["render"], {"event_id", "request_id", "input_digest", "rendered_digest", "status"}, "render")
    if not OPAQUE.fullmatch(render["event_id"]) or render["request_id"] != request["id"] or render["input_digest"] != input_digest(record) or not DIGEST.fullmatch(render["rendered_digest"]) or render["status"] != "rendered":
        raise SessionError("rendering input mismatch")
    events = record["events"]
    if not isinstance(events, list) or len(events) != 4:
        raise SessionError("invalid bounded event trace")
    ids, digests = set(), set()
    for sequence, event in enumerate(events, 1):
        _event(event, sequence, ids, digests)
    if [event["event_type"] for event in events] != ["session_created", "gate_rendered", "input_validated", "ui_checkpointed"]:
        raise SessionError("invalid event ordering")
    input_event = events[2]
    if input_event["request_id"] != request["id"] or input_event["input_event_id"] != input_event["event_id"] or (input_event["decision"] != "timeout" and input_event["human_present"] is not True):
        raise SessionError("input is not bound to human presence")
    final = _object(record["final_event"], {"event_id", "sequence", "event_type", "decision", "reason", "request_id", "input_event_id", "evidence_digest"}, "final event")
    if final["sequence"] != 5 or final["event_type"] != "validated_final" or final["decision"] not in DECISIONS or final["request_id"] != request["id"] or final["input_event_id"] != input_event["event_id"] or final["event_id"] in ids or not OPAQUE.fullmatch(final["event_id"]) or not DIGEST.fullmatch(final["evidence_digest"]):
        raise SessionError("invalid final event")
    if final["decision"] in {"approve", "reject", "clarify"} and final["reason"] != "human_selected":
        raise SessionError("invalid decision reason")
    if final["decision"] == "timeout" and final["reason"] != "session_expired":
        raise SessionError("invalid timeout reason")
    if final["decision"] == "cancel" and final["reason"] != "user_cancelled":
        raise SessionError("invalid cancellation reason")
    persistence = _object(record["persistence"], {"operation_id", "idempotency_key", "status", "event_digest", "network", "durable_state"}, "persistence")
    if not OPAQUE.fullmatch(persistence["operation_id"]) or not persistence["operation_id"].startswith("OP-") or not DIGEST.fullmatch(persistence["idempotency_key"]) or persistence["status"] != "not_performed" or persistence["event_digest"] != final_digest(final) or persistence["network"] != "not_performed" or persistence["durable_state"] != "not_performed":
        raise SessionError("unsafe or mismatched persistence")
    if require_terminal and private["state"] != "final_validated":
        raise SessionError("session is not terminal")
    if _scan(record):
        raise SessionError("private evidence leakage")
    return {"protocol": "awr-production-ui-human-gate@1.0.0", "task_revision": expected_revision, "session_id": record["session"]["id"], "decision": final["decision"], "final_event": "validated", "persistence": "not_performed", "live_ui": "not_performed", "live_coordinator": "not_performed", "network": "not_performed"}


def persist_final_event(record):
    """Prepare an idempotent Coordinator operation; never performs it."""
    result = validate(record, record["task"]["revision"])
    return {"operation_id": record["persistence"]["operation_id"], "idempotency_key": record["persistence"]["idempotency_key"], "event_digest": record["persistence"]["event_digest"], "status": "not_performed", "decision": result["decision"]}

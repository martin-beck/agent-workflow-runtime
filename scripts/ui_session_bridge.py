#!/usr/bin/env python3
"""Offline provider-neutral UI session bridge model for AR-0011."""

import hashlib
import json
import re


PROTOCOL = {"id": "awr-ui-session-bridge", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
WORKER = re.compile(r"^WRK-[A-Z0-9-]{1,63}$")
LEASE = re.compile(r"^LSE-[A-Z0-9-]{1,63}$")
EVENT = re.compile(r"^UI-[A-Z0-9-]{1,63}$")
PROJECT = re.compile(r"^[0-9a-f]{40}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)

EVENT_TYPES = {"session_started", "ui_rendered", "ui_input", "ui_checkpointed", "ui_interrupt_requested", "ui_interruption_acknowledged"}
FINAL_TYPES = {"safe_exit", "interrupted", "completed"}
DISPOSITIONS = {"started", "observed", "accepted", "acknowledged"}
FINAL_DISPOSITIONS = {"safe_exit", "interrupted", "completed"}
REASONS = {"user_requested", "host_shutdown", "interruption_acknowledged", "session_completed"}


class BridgeError(ValueError):
    """A fail-closed UI bridge violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise BridgeError("malformed " + name)
    return value


def _private(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                errors.append(location + "." + str(key))
            _private(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _private(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE.search(value):
        errors.append(location)
    return errors


def _binding(record, expected_revision, expected_task, expected_project, expected_worktree, expected_session, expected_lease):
    task = _object(record["task"], {"id", "revision"}, "task")
    project = _object(record["project"], {"key", "revision"}, "project")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    session = _object(record["session"], {"id"}, "session")
    lease = _object(record["lease"], {"id", "worker_id", "digest"}, "lease")
    if task != {"id": expected_task, "revision": expected_revision} or not TASK.fullmatch(task["id"]):
        raise BridgeError("stale or invalid task binding")
    if project["key"] != expected_project or not PROJECT.fullmatch(project["revision"]):
        raise BridgeError("invalid project binding")
    if worktree["key"] != expected_worktree or not WORKTREE.fullmatch(worktree["key"]) or not DIGEST.fullmatch(worktree["digest"]):
        raise BridgeError("invalid worktree binding")
    if session["id"] != expected_session or not SESSION.fullmatch(session["id"]):
        raise BridgeError("invalid session binding")
    if lease["id"] != expected_lease or not LEASE.fullmatch(lease["id"]) or not WORKER.fullmatch(lease["worker_id"]) or not DIGEST.fullmatch(lease["digest"]):
        raise BridgeError("invalid lease binding")


def _validate_event(event, sequence, *, final=False):
    fields = {"event_id", "sequence", "event_type", "disposition", "evidence_digest"}
    if final:
        fields |= {"reason"}
    _object(event, fields, "final event" if final else "UI event")
    if not isinstance(event["sequence"], int) or isinstance(event["sequence"], bool) or event["sequence"] != sequence:
        raise BridgeError("invalid UI event sequence")
    if not EVENT.fullmatch(str(event["event_id"])) or not DIGEST.fullmatch(str(event["evidence_digest"])):
        raise BridgeError("invalid UI event identity or digest")
    allowed = FINAL_TYPES if final else EVENT_TYPES
    dispositions = FINAL_DISPOSITIONS if final else DISPOSITIONS
    if event["event_type"] not in allowed or event["disposition"] not in dispositions:
        raise BridgeError("invalid UI event type or disposition")
    if final and event["reason"] not in REASONS:
        raise BridgeError("invalid final-event reason")
    if not final and event["event_type"] == "session_started" and sequence != 1:
        raise BridgeError("session_started must be first")


def binding_digest(record):
    return sha256(canonical_bytes({key: record[key] for key in ("task", "project", "worktree", "session", "lease")}))


def trace_digest(record):
    return sha256(canonical_bytes({"events": record["events"], "final_event": record["final_event"]}))


def validate_bridge(record, expected_revision=1, *, expected_task="AR-0011", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0011", expected_session="SES-AR0011-REFERENCE", expected_lease="LSE-AR0011-REFERENCE"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "lease", "events", "final_event", "resume"}
    _object(record, top, "bridge record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise BridgeError("unsupported bridge protocol")
    _binding(record, expected_revision, expected_task, expected_project, expected_worktree, expected_session, expected_lease)
    events = record["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= 32:
        raise BridgeError("invalid bounded UI event count")
    ids, digests = set(), set()
    for sequence, event in enumerate(events, 1):
        _validate_event(event, sequence)
        if event["event_id"] in ids or event["evidence_digest"] in digests:
            raise BridgeError("replayed UI event material")
        ids.add(event["event_id"]); digests.add(event["evidence_digest"])
    if events[0]["event_type"] != "session_started":
        raise BridgeError("trace must start with session_started")
    final = record["final_event"]
    _validate_event(final, len(events) + 1, final=True)
    if final["event_id"] in ids or final["evidence_digest"] in digests:
        raise BridgeError("replayed final event material")
    if final["event_type"] == "safe_exit" and final["reason"] not in {"user_requested", "host_shutdown"}:
        raise BridgeError("safe exit requires a safe-exit reason")
    if final["event_type"] == "interrupted" and final["reason"] != "interruption_acknowledged":
        raise BridgeError("interrupted final event requires acknowledgement")
    if final["event_type"] == "completed" and final["reason"] != "session_completed":
        raise BridgeError("completed final event requires completion reason")
    resume = record["resume"]
    if final["event_type"] in {"safe_exit", "interrupted"}:
        _object(resume, {"status", "checkpoint_event_id", "prior_trace_digest", "binding_digest"}, "resume")
        if resume["status"] != "resumable" or not EVENT.fullmatch(str(resume["checkpoint_event_id"])) or resume["checkpoint_event_id"] not in ids:
            raise BridgeError("invalid resumable checkpoint")
        if not DIGEST.fullmatch(resume["prior_trace_digest"]) or resume["prior_trace_digest"] != trace_digest(record):
            raise BridgeError("resume trace digest mismatch")
        if resume["binding_digest"] != binding_digest(record):
            raise BridgeError("resume binding mismatch")
        if not any(event["event_id"] == resume["checkpoint_event_id"] and event["event_type"] == "ui_checkpointed" for event in events):
            raise BridgeError("resume requires a UI checkpoint")
    elif resume is not None:
        raise BridgeError("completed session cannot advertise resume")
    if _private(record):
        raise BridgeError("private UI bridge material")
    return {"protocol": "awr-ui-session-bridge@1.0.0", "task_revision": expected_revision, "session_id": record["session"]["id"], "events": len(events) + 1, "final": final["event_type"], "resumable": resume is not None}


def validate_resume(record, expected_revision=1):
    result = validate_bridge(record, expected_revision)
    if not result["resumable"]:
        raise BridgeError("session is not resumable")
    return result

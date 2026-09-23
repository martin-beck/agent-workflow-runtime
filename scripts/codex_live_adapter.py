#!/usr/bin/env python3
"""Offline deterministic model for the AR-0033 Codex live-adapter boundary."""

import hashlib
import json
import re


TASK = {"id": "AR-0033", "revision": 3}
ADAPTER = {"id": "codex-live", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
CODE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
FORBIDDEN = re.compile(
    r"credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|personal.?data|raw.?output|argv|command|executable",
    re.I,
)


class LiveAdapterError(ValueError):
    """Raised when an offline observation is not admissible."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            # The gate vocabulary contains one deliberately fixed reference-only
            # credential marker.  It is metadata, not a credential payload; the
            # same key remains forbidden everywhere else.
            gate_reference = path == ("gates",) and key == "credential" and child == "reference_only"
            if FORBIDDEN.search(str(key)) and not gate_reference:
                return False
            if not _safe(child, path + (str(key),)):
                return False
        return True
    if isinstance(value, list):
        return all(_safe(v, path) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(
        r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|"
        r"BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


def _binding(value):
    if not isinstance(value, dict) or set(value) != {"task", "project", "worktree", "session"}:
        raise LiveAdapterError("complete binding required")
    if value["task"] != TASK:
        raise LiveAdapterError("stale or incorrect task revision")
    project = value["project"]
    if not isinstance(project, dict) or set(project) != {"id", "revision"} or project["id"] != "agent-workflow-runtime" or not DIGEST.fullmatch(str(project["revision"])):
        raise LiveAdapterError("invalid project revision")
    worktree = value["worktree"]
    if not isinstance(worktree, dict) or set(worktree) != {"key", "digest"} or not KEY.fullmatch(str(worktree["key"])) or not DIGEST.fullmatch(str(worktree["digest"])):
        raise LiveAdapterError("invalid worktree identity")
    session = value["session"]
    if not isinstance(session, dict) or set(session) != {"id"} or not SESSION.fullmatch(str(session["id"])):
        raise LiveAdapterError("invalid session identity")
    return value


def _event_digest(event):
    return sha256(canonical_bytes({key: value for key, value in event.items() if key != "event_digest"}))


def capability_report():
    body = {"adapter": ADAPTER, "capabilities": ["discover", "start", "request", "response", "interrupt", "close", "fail"], "limits": {"max_trace_records": 64, "max_in_flight": 1, "max_reference_bytes": 256}}
    return {**body, "digest": sha256(canonical_bytes(body))}


def validate_record(record):
    required = {"task", "project", "worktree", "session", "adapter", "capability_report", "gates", "trace", "terminal"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise LiveAdapterError("unknown, missing, or privacy-bearing envelope field")
    binding = {key: record[key] for key in ("task", "project", "worktree", "session")}
    _binding(binding)
    if record["adapter"] != ADAPTER or record["capability_report"] != capability_report():
        raise LiveAdapterError("adapter identity or capability digest mismatch")
    if record["gates"] != {"credential": "reference_only", "human_approval": "not_granted", "network": "denied", "provider": "not_selected"}:
        raise LiveAdapterError("live gates must remain closed")
    trace = record["trace"]
    if not isinstance(trace, list) or not trace or len(trace) > 64:
        raise LiveAdapterError("trace must be bounded and non-empty")
    transitions = {
        ("admitted", "discover", "discovered"),
        ("discovered", "start", "active"),
        ("active", "request", "awaiting_response"),
        ("awaiting_response", "response", "active"),
        ("active", "interrupt", "interrupted"),
        ("active", "close", "closed"),
        ("active", "fail", "failed"),
        ("awaiting_response", "interrupt", "interrupted"),
        ("awaiting_response", "fail", "failed"),
    }
    state, in_flight, seen = "admitted", None, set()
    for sequence, event in enumerate(trace, 1):
        fields = {"sequence", "operation", "state_before", "state_after", "binding", "adapter", "request_id", "evidence_digest", "event_digest"}
        if not isinstance(event, dict) or set(event) != fields or event["sequence"] != sequence or sequence in seen:
            raise LiveAdapterError("invalid, unknown, or replayed trace event")
        seen.add(sequence)
        if event["binding"] != binding or event["adapter"] != ADAPTER or event["state_before"] != state or (state, event["operation"], event["state_after"]) not in transitions:
            raise LiveAdapterError("crossed or unauthorized lifecycle transition")
        if not DIGEST.fullmatch(str(event["evidence_digest"])) or event["event_digest"] != _event_digest(event):
            raise LiveAdapterError("invalid event evidence or digest")
        request_id = event["request_id"]
        if request_id is not None and (not isinstance(request_id, str) or not re.fullmatch(r"REQ-[A-Z0-9-]{1,63}", request_id)):
            raise LiveAdapterError("invalid request identity")
        if event["operation"] == "request":
            if request_id is None or in_flight is not None:
                raise LiveAdapterError("request requires one empty in-flight slot")
            in_flight = request_id
        elif event["operation"] == "response":
            if request_id != in_flight:
                raise LiveAdapterError("response does not correlate to the outstanding request")
            in_flight = None
        elif event["operation"] in {"interrupt", "close", "fail"} and request_id is not None:
            raise LiveAdapterError("terminal operation cannot carry a request")
        state = event["state_after"]
    if state not in {"interrupted", "closed", "failed"} or in_flight is not None:
        raise LiveAdapterError("trace must terminate with no outstanding request")
    terminal = {"state": state, "execute": False, "provider": "not_selected", "network": "denied", "remote_verification": "unverified", "durable_state": "not_performed"}
    if record["terminal"] != terminal:
        raise LiveAdapterError("terminal observation is not fail-closed")
    return {"contract": "awr-codex-live-adapter@1.0.0", "records": len(trace), "task_revision": 3, "terminal_state": state, "execute": False}

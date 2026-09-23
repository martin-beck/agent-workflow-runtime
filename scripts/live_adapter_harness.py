#!/usr/bin/env python3
"""Deterministic, non-executing model for the AR-0032 live adapter boundary."""

import hashlib
import json
import re


TASK = {"id": "AR-0032", "revision": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
NAME = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output", re.I)


class HarnessError(ValueError):
    """Raised when the supplied offline observation is not admissible."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any((str(key) in {"argv", "command"} or FORBIDDEN.search(str(key))) and not (str(key) == "credential" and child in {"reference_only", "not_supplied"}) for key, child in value.items()) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


def _binding(record):
    if record.get("task") != TASK:
        raise HarnessError("stale or incorrect task revision")
    project = record.get("project")
    if not isinstance(project, dict) or set(project) != {"id", "revision"} or project["id"] != "agent-workflow-runtime" or not DIGEST.fullmatch(str(project["revision"])):
        raise HarnessError("invalid project revision binding")
    worktree = record.get("worktree")
    if not isinstance(worktree, dict) or set(worktree) != {"key", "digest"} or not KEY.fullmatch(str(worktree["key"])) or not DIGEST.fullmatch(str(worktree["digest"])):
        raise HarnessError("invalid worktree binding")
    session = record.get("session")
    if not isinstance(session, dict) or set(session) != {"id"} or not SESSION.fullmatch(str(session["id"])):
        raise HarnessError("invalid session binding")
    return (record["task"], project, worktree, session)


def _adapter(adapter):
    if not isinstance(adapter, dict) or set(adapter) != {"id", "version"} or not NAME.fullmatch(str(adapter.get("id", ""))) or not SEMVER.fullmatch(str(adapter.get("version", ""))):
        raise HarnessError("invalid adapter identity")


def capability_report(adapter, capabilities):
    _adapter(adapter)
    if not isinstance(capabilities, list) or not capabilities or len(capabilities) > 16 or len(set(capabilities)) != len(capabilities) or any(not isinstance(c, str) or not NAME.fullmatch(c) for c in capabilities):
        raise HarnessError("bounded unique capabilities required")
    body = {"adapter": adapter, "capabilities": capabilities, "limits": {"max_trace_records": 64, "max_output_bytes": 4096, "max_duration_ms": 30000}}
    return {**body, "digest": sha256(canonical_bytes(body))}


def _event_digest(event):
    body = {k: v for k, v in event.items() if k != "event_digest"}
    return sha256(canonical_bytes(body))


def validate_record(record):
    required = {"task", "project", "worktree", "session", "adapter", "capability_report", "admission", "transport", "trace", "terminal"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise HarnessError("unknown, missing, or privacy-bearing envelope field")
    binding = _binding(record)
    _adapter(record["adapter"])
    report = record["capability_report"]
    if report != capability_report(record["adapter"], report.get("capabilities")):
        raise HarnessError("capability report digest or identity mismatch")
    admission = record["admission"]
    if not isinstance(admission, dict) or set(admission) != {"required", "granted", "grant_digest", "execute"} or admission["required"] != ["start", "send", "interrupt", "resume", "close"] or admission["granted"] != admission["required"] or admission["execute"] is not False:
        raise HarnessError("invalid non-executing capability admission")
    if admission["grant_digest"] != sha256(canonical_bytes({"adapter": record["adapter"], "capabilities": admission["granted"], "task": TASK})):
        raise HarnessError("capability grant digest mismatch")
    transport = record["transport"]
    if not isinstance(transport, dict) or set(transport) != {"mode", "argv_digest", "limits", "gates"} or transport["mode"] != "bounded_process" or not DIGEST.fullmatch(str(transport["argv_digest"])):
        raise HarnessError("invalid bounded transport declaration")
    if transport["limits"] != {"duration_ms": 30000, "output_bytes": 4096, "processes": 1, "cancel_grace_ms": 1000}:
        raise HarnessError("invalid process limits")
    if transport["gates"] != {"credential": "reference_only", "network": "denied", "provider": "not_selected", "human_approval": "not_granted"}:
        raise HarnessError("live execution gates must remain closed")
    trace = record["trace"]
    if not isinstance(trace, list) or not trace or len(trace) > 64:
        raise HarnessError("trace must be bounded and non-empty")
    states = ["admitted", "started", "active", "interrupted", "resumed", "completed"]
    allowed = {("admitted", "start", "started"), ("started", "send", "active"), ("active", "interrupt", "interrupted"), ("interrupted", "resume", "resumed"), ("resumed", "close", "completed")}
    state = "admitted"
    seen = set()
    for index, event in enumerate(trace, 1):
        fields = {"sequence", "operation", "state_before", "state_after", "binding", "adapter", "evidence_digest", "event_digest"}
        if not isinstance(event, dict) or set(event) != fields or event["sequence"] != index or index in seen:
            raise HarnessError("invalid or replayed trace event")
        seen.add(index)
        if event["binding"] != {"task": TASK, "project": record["project"], "worktree": record["worktree"], "session": record["session"]} or event["adapter"] != record["adapter"]:
            raise HarnessError("crossed trace binding")
        if event["state_before"] != state or (state, event["operation"], event["state_after"]) not in allowed or event["state_after"] not in states:
            raise HarnessError("unauthorized state transition")
        if not DIGEST.fullmatch(str(event["evidence_digest"])) or event["event_digest"] != _event_digest(event):
            raise HarnessError("event digest mismatch")
        state = event["state_after"]
    if state != "completed" or record["terminal"] != {"state": "completed", "execute": False, "remote_verification": "unverified", "durable_state": "not_performed"}:
        raise HarnessError("trace must end in explicit offline completion")
    return {"contract": "awr-live-adapter-harness@1.0.0", "records": len(trace), "task_revision": TASK["revision"], "terminal": state, "execute": False}

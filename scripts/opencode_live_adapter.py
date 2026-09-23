#!/usr/bin/env python3
"""Offline deterministic model for the AR-0034 OpenCode live boundary."""

import hashlib
import json
import re


TASK = {"id": "AR-0034", "revision": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
FORBIDDEN = re.compile(
    r"credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|personal.?data|raw.?output|argv|command",
    re.I,
)


class OpenCodeLiveError(ValueError):
    """Raised when an offline observation is not admissible."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(
            FORBIDDEN.search(str(key)) and not (str(key) == "credential" and child == "reference_only")
            for key, child in value.items()
        ) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


def _binding(record):
    if record.get("task") != TASK:
        raise OpenCodeLiveError("stale or incorrect task revision")
    project = record.get("project")
    if not isinstance(project, dict) or set(project) != {"id", "revision"} or project["id"] != "agent-workflow-runtime" or not DIGEST.fullmatch(str(project["revision"])):
        raise OpenCodeLiveError("invalid project revision binding")
    worktree = record.get("worktree")
    if not isinstance(worktree, dict) or set(worktree) != {"key", "digest"} or not KEY.fullmatch(str(worktree["key"])) or not DIGEST.fullmatch(str(worktree["digest"])):
        raise OpenCodeLiveError("invalid worktree binding")
    session = record.get("session")
    if not isinstance(session, dict) or set(session) != {"id"} or not SESSION.fullmatch(str(session["id"])):
        raise OpenCodeLiveError("invalid session binding")
    return {"task": TASK, "project": project, "worktree": worktree, "session": session}


def _adapter(value):
    if not isinstance(value, dict) or set(value) != {"id", "version"} or value["id"] != "opencode-live" or not SEMVER.fullmatch(str(value["version"])):
        raise OpenCodeLiveError("invalid adapter identity")


def _request_digest(request):
    return digest(canonical_bytes({key: value for key, value in request.items() if key != "request_digest"}))


def _response_digest(response):
    return digest(canonical_bytes({key: value for key, value in response.items() if key != "response_digest"}))


def _event_digest(event):
    return digest(canonical_bytes({key: value for key, value in event.items() if key != "event_digest"}))


def validate_record(record):
    required = {"task", "project", "worktree", "session", "adapter", "capabilities", "gates", "request", "response", "trace", "terminal"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise OpenCodeLiveError("unknown, missing, or privacy-bearing envelope field")
    binding = _binding(record)
    _adapter(record["adapter"])
    if record["capabilities"] != {"request": True, "response": True, "interrupt": True, "resume": True}:
        raise OpenCodeLiveError("capability admission is not exact")
    if record["gates"] != {"credential": "reference_only", "human_approval": "not_granted", "network": "denied", "provider": "not_selected"}:
        raise OpenCodeLiveError("live gates must remain closed")
    request = record["request"]
    if not isinstance(request, dict) or set(request) != {"id", "sequence", "operation", "input_digest", "request_digest"} or request["id"] != "REQ-AR0034-001" or request["sequence"] != 1 or request["operation"] != "session.start" or not DIGEST.fullmatch(str(request["input_digest"])) or request["request_digest"] != _request_digest(request):
        raise OpenCodeLiveError("invalid deterministic request")
    response = record["response"]
    if not isinstance(response, dict) or set(response) != {"request_id", "sequence", "status", "output_digest", "response_digest"} or response["request_id"] != request["id"] or response["sequence"] != 1 or response["status"] != "accepted" or not DIGEST.fullmatch(str(response["output_digest"])) or response["response_digest"] != _response_digest(response):
        raise OpenCodeLiveError("missing, replayed, or mismatched response")
    trace = record["trace"]
    if not isinstance(trace, list) or len(trace) != 5:
        raise OpenCodeLiveError("trace must contain exactly five bounded transitions")
    allowed = {("admitted", "request", "requested"), ("requested", "response", "responding"), ("responding", "interrupt", "interrupted"), ("interrupted", "resume", "resumed"), ("resumed", "close", "completed")}
    state = "admitted"
    seen = set()
    for index, event in enumerate(trace, 1):
        fields = {"sequence", "operation", "state_before", "state_after", "binding", "request_digest", "response_digest", "event_digest"}
        if not isinstance(event, dict) or set(event) != fields or event["sequence"] != index or index in seen:
            raise OpenCodeLiveError("invalid or replayed lifecycle event")
        seen.add(index)
        if event["binding"] != binding or event["state_before"] != state or (state, event["operation"], event["state_after"]) not in allowed:
            raise OpenCodeLiveError("unauthorized or crossed lifecycle transition")
        if event["request_digest"] != request["request_digest"] or event["response_digest"] != response["response_digest"] or event["event_digest"] != _event_digest(event):
            raise OpenCodeLiveError("lifecycle digest mismatch")
        state = event["state_after"]
    terminal = {"state": "completed", "execute": False, "remote_verification": "unverified", "durable_state": "not_performed"}
    if state != "completed" or record["terminal"] != terminal:
        raise OpenCodeLiveError("trace must end in explicit offline completion")
    return {"contract": "awr-opencode-live-adapter@1.0.0", "request": request["id"], "response": response["request_id"], "events": len(trace), "task_revision": TASK["revision"], "execute": False}

#!/usr/bin/env python3
"""Offline reference model for the provider-neutral OpenCode-style mapping."""

import hashlib
import json
import re


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TASK_ID = re.compile(r"^AR-[0-9]{4}$")
SESSION_ID = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output", re.I)


class OpenCodeAdapterError(ValueError):
    """Raised when a native envelope cannot be normalized safely."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


MAPPING = {
    "session.created": ("session_started", ("session_digest",), "accepted"),
    "message.part": ("plan_proposed", ("part_kind", "content_digest"), "accepted"),
    "tool.started": ("tool_call", ("tool_kind", "call_digest"), "started"),
    "tool.completed": ("tool_call", ("tool_kind", "call_digest"), "completed"),
    "file.changed": ("file_change", ("change_digest", "file_count"), "accepted"),
    "session.failed": ("failed", ("error_code",), "failed"),
    "session.completed": ("completed", ("result_digest",), "completed"),
}
COMMON = {"sequence", "kind", "task", "session", "payload_digest"}


def _safe(value):
    if isinstance(value, dict):
        return not any(FORBIDDEN.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


def _binding(native, revision):
    if set(native) != COMMON or not isinstance(native["sequence"], int) or native["sequence"] < 1:
        raise OpenCodeAdapterError("unknown or malformed native envelope field")
    if native["task"] != {"id": "AR-0016", "revision": revision}:
        raise OpenCodeAdapterError("stale or cross-task revision")
    session = native["session"]
    if not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"} or not SESSION_ID.fullmatch(str(session["id"])) or not WORKTREE.fullmatch(str(session["worktree_key"])) or not DIGEST.fullmatch(str(session["worktree_digest"])):
        raise OpenCodeAdapterError("invalid session/worktree binding")
    if not DIGEST.fullmatch(str(native["payload_digest"])) or not _safe(native):
        raise OpenCodeAdapterError("invalid digest or privacy-bearing native data")
    return session


def normalize(native, revision=5):
    session = _binding(native, revision)
    kind = native["kind"]
    if kind not in MAPPING:
        raise OpenCodeAdapterError("unsupported native event kind")
    event_type, required, disposition = MAPPING[kind]
    payload = native["payload_digest"]
    # The fixture carries a digest of the safe payload projection. This model
    # intentionally never accepts or reconstructs native text/content.
    projected = {"kind": kind, "payload_digest": payload}
    if kind == "session.created":
        projected["session_digest"] = payload
    elif kind == "message.part":
        projected.update({"part_kind": "plan", "content_digest": payload})
    elif kind.startswith("tool."):
        projected.update({"tool_kind": "bounded", "call_digest": payload})
    elif kind == "file.changed":
        projected.update({"change_digest": payload, "file_count": 1})
    elif kind == "session.failed":
        projected["error_code"] = "synthetic_failure"
    elif kind == "session.completed":
        projected["result_digest"] = payload
    if any(key not in projected for key in required):
        raise OpenCodeAdapterError("native payload projection is incomplete")
    body = {"sequence": native["sequence"], "event_type": event_type, "task": native["task"], "session": session, "adapter": {"id": "opencode-style", "version": "1.0.0"}, "disposition": disposition, "evidence_digest": digest(canonical_bytes(projected))}
    return {**body, "event_digest": digest(canonical_bytes(body))}


def replay(native_events, revision=5):
    if not isinstance(native_events, list) or not native_events or len(native_events) > 64:
        raise OpenCodeAdapterError("replay must be a bounded non-empty list")
    normalized = []
    seen = set()
    native_seen = set()
    binding = None
    for index, native in enumerate(native_events, 1):
        if native.get("sequence") != index:
            raise OpenCodeAdapterError("sequence is not contiguous")
        native_identity = (native.get("kind"), native.get("payload_digest"))
        if native_identity in native_seen:
            raise OpenCodeAdapterError("replayed native event")
        native_seen.add(native_identity)
        event = normalize(native, revision)
        current_binding = (event["task"]["revision"], event["session"]["id"], event["session"]["worktree_key"], event["session"]["worktree_digest"])
        if binding is None:
            binding = current_binding
        elif current_binding != binding:
            raise OpenCodeAdapterError("replay crosses task, session, or worktree binding")
        if event["event_digest"] in seen:
            raise OpenCodeAdapterError("replayed event digest")
        seen.add(event["event_digest"])
        normalized.append(event)
    return normalized

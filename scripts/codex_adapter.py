#!/usr/bin/env python3
"""Offline reference model for the provider-neutral AR-0015 adapter contract."""

import hashlib
import json
import re
from dataclasses import dataclass


TASK_ID = "AR-0015"
ADAPTER_ID = "codex-style"
ADAPTER_VERSION = "1.0.0"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
CODE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
FORBIDDEN = re.compile(
    r"credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|personal.?data|raw.?output|command|executable",
    re.I,
)


class AdapterError(ValueError):
    """Raised when an offline adapter operation is invalid."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(FORBIDDEN.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


@dataclass(frozen=True)
class CapabilityReport:
    adapter_id: str = ADAPTER_ID
    adapter_version: str = ADAPTER_VERSION
    capabilities: tuple = ("discover", "start", "turn", "interrupt", "close", "fail")

    def as_dict(self):
        body = {
            "adapter": {"id": self.adapter_id, "version": self.adapter_version},
            "capabilities": list(self.capabilities),
            "limits": {"max_turns": 64, "max_reference_bytes": 256, "max_trace_records": 128},
        }
        return {**body, "digest": sha256(canonical_bytes(body))}


class CodexStyleAdapter:
    """Turn-oriented adapter model; it has no provider, process, or network seam."""

    def __init__(self, expected_revision=5):
        if not isinstance(expected_revision, int) or expected_revision < 1:
            raise AdapterError("invalid Coordinator revision")
        self.expected_revision = expected_revision
        self.state = "undiscovered"
        self.binding = None
        self.turns = 0

    def discover(self):
        if self.state != "undiscovered":
            raise AdapterError("discovery is single-use")
        self.state = "discovered"
        return {"operation": "discover", "state": self.state, "adapter": {"id": ADAPTER_ID, "version": ADAPTER_VERSION}}

    def capabilities(self):
        if self.state not in {"discovered", "active"}:
            raise AdapterError("capability discovery requires a non-terminal discovered session")
        return {"operation": "capabilities", "state": self.state, **CapabilityReport().as_dict()}

    def start(self, task, session):
        if self.state != "discovered":
            raise AdapterError("start requires discovery")
        if task != {"id": TASK_ID, "revision": self.expected_revision}:
            raise AdapterError("exact current task revision required")
        if (not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"}
                or not SESSION.fullmatch(str(session.get("id", "")))
                or not WORKTREE.fullmatch(str(session.get("worktree_key", "")))
                or not DIGEST.fullmatch(str(session.get("worktree_digest", "")))
                or not _safe(session)):
            raise AdapterError("malformed or private session binding")
        self.binding = {"task": dict(task), "session": dict(session), "adapter": {"id": ADAPTER_ID, "version": ADAPTER_VERSION}}
        self.state = "active"
        return self._result("start", "started")

    def turn(self, reference_digest):
        if self.state != "active" or not DIGEST.fullmatch(str(reference_digest)):
            raise AdapterError("active turns require a bounded digest reference")
        self.turns += 1
        if self.turns > 64:
            raise AdapterError("turn limit exceeded")
        return self._result("turn", "accepted", reference_digest=reference_digest, turn=self.turns)

    def interrupt(self):
        if self.state != "active":
            raise AdapterError("interrupt requires an active session")
        self.state = "interrupted"
        return self._result("interrupt", "interrupted")

    def close(self):
        if self.state != "active":
            raise AdapterError("close requires an active session")
        self.state = "closed"
        return self._result("close", "completed")

    def fail(self, code):
        if self.state != "active" or not isinstance(code, str) or not CODE.fullmatch(code):
            raise AdapterError("failure requires an active session and bounded code")
        self.state = "failed"
        return self._result("fail", "failed", code=code)

    def _result(self, operation, disposition, **extra):
        return {"operation": operation, "state": self.state, "disposition": disposition, **self.binding, **extra}

#!/usr/bin/env python3
"""Offline, provider-neutral reference implementation of AR-0003."""

import hashlib
import json
import re
from dataclasses import dataclass


ID = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ADAPTER = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output", re.I)
STATES = {"undiscovered", "discovered", "started", "active", "terminated", "failed"}
CAPABILITIES = ("discover", "start", "interact", "terminate", "fail")


class AdapterError(ValueError):
    """Raised for invalid input or an invalid lifecycle transition."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        if any(FORBIDDEN.search(str(key)) for key in value):
            return False
        return all(_safe(child) for child in value.values())
    if isinstance(value, list):
        return all(_safe(child) for child in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


@dataclass(frozen=True)
class CapabilityReport:
    adapter_id: str
    adapter_version: str
    capabilities: tuple
    limits: dict

    def as_dict(self):
        body = {"adapter": {"id": self.adapter_id, "version": self.adapter_version}, "capabilities": list(self.capabilities), "limits": dict(self.limits)}
        return {**body, "digest": sha256(canonical_bytes(body))}


class ReferenceAdapter:
    """Deterministic lifecycle boundary; it deliberately has no provider seam."""

    def __init__(self, adapter_id="reference", adapter_version="1.0.0", expected_revision=5):
        if not ADAPTER.fullmatch(adapter_id) or not SEMVER.fullmatch(adapter_version) or expected_revision < 1:
            raise AdapterError("invalid adapter identity or revision")
        self.adapter_id = adapter_id
        self.adapter_version = adapter_version
        self.expected_revision = expected_revision
        self.state = "undiscovered"
        self.binding = None
        self._sequence = 0

    def capabilities(self):
        if self.state not in {"discovered", "started", "active"}:
            raise AdapterError("capabilities require discovery")
        report = CapabilityReport(self.adapter_id, self.adapter_version, CAPABILITIES, {"max_operation": 32, "max_capabilities": 16, "max_trace_records": 64})
        return {"operation": "capabilities", **report.as_dict(), "state": self.state}

    def discover(self):
        if self.state != "undiscovered":
            raise AdapterError("discovery is single-use")
        self.state = "discovered"
        return {"operation": "discover", "state": self.state, "adapter": {"id": self.adapter_id, "version": self.adapter_version}}

    def start(self, task, session):
        if self.state != "discovered":
            raise AdapterError("start requires discovery and a non-terminal state")
        if not isinstance(task, dict) or set(task) != {"id", "revision"} or not TASK.fullmatch(str(task["id"])) or task["revision"] != self.expected_revision:
            raise AdapterError("exact current task revision required")
        if not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"} or not ID.fullmatch(str(session["id"])) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session["worktree_key"])) or not DIGEST.fullmatch(str(session["worktree_digest"])):
            raise AdapterError("malformed session binding")
        if not _safe({"task": task, "session": session}):
            raise AdapterError("privacy violation")
        self.binding = {"task": dict(task), "session": dict(session), "adapter": {"id": self.adapter_id, "version": self.adapter_version}}
        self.state = "started"
        return self._result("start", "started")

    def interact(self, request_digest):
        if self.state not in {"started", "active"}:
            raise AdapterError("interaction requires an active session")
        if not isinstance(request_digest, str) or not DIGEST.fullmatch(request_digest):
            raise AdapterError("interaction requires a bounded digest reference")
        self.state = "active"
        return self._result("interact", "accepted", request_digest=request_digest)

    def terminate(self, reason="completed"):
        if self.state not in {"started", "active"}:
            raise AdapterError("termination requires a running session")
        if reason not in {"completed", "interrupted", "cancelled"}:
            raise AdapterError("unsupported termination reason")
        self.state = "terminated"
        return self._result("terminate", reason)

    def fail(self, code):
        if self.state not in {"started", "active"} or not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", code):
            raise AdapterError("failure requires a running session and bounded code")
        self.state = "failed"
        return self._result("fail", "failed", code=code)

    def _result(self, operation, disposition, **extra):
        self._sequence += 1
        result = {"sequence": self._sequence, "operation": operation, "state": self.state, "disposition": disposition, **self.binding, **extra}
        return result

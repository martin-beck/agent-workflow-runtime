#!/usr/bin/env python3
"""Offline provider-neutral OpenDesk-style adapter reference model."""

import hashlib
import json
import re
from dataclasses import dataclass

TASK = re.compile(r"^AR-[0-9]{4}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ADAPTER = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output", re.I)
KNOWN_CAPABILITIES = ("conversation", "streaming", "structured_output", "tool_use", "file_read", "file_write", "resume")
STATES = {"undiscovered", "ready", "active", "terminated", "failed"}


class AdapterError(ValueError):
    """Raised when an input or lifecycle transition is invalid."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(FORBIDDEN.search(str(key)) for key in value) and all(_safe(child) for child in value.values())
    if isinstance(value, list):
        return all(_safe(child) for child in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


@dataclass(frozen=True)
class CapabilityReport:
    adapter_id: str
    adapter_version: str
    capabilities: tuple

    def as_dict(self):
        body = {"adapter": {"id": self.adapter_id, "version": self.adapter_version}, "capabilities": list(self.capabilities), "limits": {"max_capabilities": 16, "max_request_digest": 72, "max_trace_records": 64}}
        return {**body, "digest": sha256(canonical_bytes(body))}


class OpenDeskStyleAdapter:
    """Deterministic contract model; it has no provider, process, or network seam."""

    def __init__(self, capabilities=("conversation",), adapter_id="opendesk-style", adapter_version="1.0.0", expected_revision=5):
        if not ADAPTER.fullmatch(adapter_id) or not SEMVER.fullmatch(adapter_version) or expected_revision < 1:
            raise AdapterError("invalid adapter identity or revision")
        if not isinstance(capabilities, (tuple, list)) or not capabilities or len(capabilities) > 16 or len(set(capabilities)) != len(capabilities):
            raise AdapterError("capabilities must be a bounded unique list")
        if any(capability not in KNOWN_CAPABILITIES for capability in capabilities):
            raise AdapterError("unknown capability")
        self.adapter_id = adapter_id
        self.adapter_version = adapter_version
        self.expected_revision = expected_revision
        self.supported = tuple(capabilities)
        self.state = "undiscovered"
        self.binding = None

    def discover(self):
        if self.state != "undiscovered":
            raise AdapterError("discovery is single-use")
        self.state = "ready"
        return {"operation": "discover", "state": self.state, "adapter": {"id": self.adapter_id, "version": self.adapter_version}}

    def capabilities(self):
        if self.state not in {"ready", "active"}:
            raise AdapterError("capabilities require discovery")
        report = CapabilityReport(self.adapter_id, self.adapter_version, self.supported)
        return {"operation": "capabilities", **report.as_dict(), "state": self.state}

    def start(self, task, session):
        if self.state != "ready":
            raise AdapterError("start requires discovery")
        if not isinstance(task, dict) or set(task) != {"id", "revision"} or not TASK.fullmatch(str(task["id"])) or task["id"] != "AR-0017" or task["revision"] != self.expected_revision:
            raise AdapterError("exact current task revision required")
        if not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"} or not SESSION.fullmatch(str(session["id"])) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session["worktree_key"])) or not DIGEST.fullmatch(str(session["worktree_digest"])) or not _safe({"task": task, "session": session}):
            raise AdapterError("malformed or private session binding")
        self.binding = {"task": dict(task), "session": dict(session), "adapter": {"id": self.adapter_id, "version": self.adapter_version}}
        return self._result("start", "started", next_state="active")

    def request(self, capability, request_digest):
        if self.state not in {"ready", "active"} or self.binding is None:
            raise AdapterError("request requires a bound session")
        if capability not in KNOWN_CAPABILITIES:
            raise AdapterError("unknown capability")
        if not isinstance(request_digest, str) or not DIGEST.fullmatch(request_digest):
            raise AdapterError("request requires a bounded digest reference")
        if capability not in self.supported:
            return self._result("request", "unsupported_capability", capability=capability, execute=False, next_state=self.state, advance=False)
        return self._result("request", "accepted", capability=capability, request_digest=request_digest, execute=False, next_state="active")

    def terminate(self, reason="completed"):
        if self.state not in {"ready", "active"}:
            raise AdapterError("termination requires a running session")
        if reason not in {"completed", "interrupted", "cancelled"}:
            raise AdapterError("unsupported termination reason")
        return self._result("terminate", reason, next_state="terminated")

    def fail(self, code):
        if self.state not in {"ready", "active"} or not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", code):
            raise AdapterError("failure requires a running session and bounded code")
        return self._result("fail", "failed", code=code, next_state="failed")

    def _result(self, operation, disposition, next_state, advance=True, **extra):
        result = {"operation": operation, "state": self.state, "disposition": disposition, **self.binding, **extra}
        if advance:
            self.state = next_state
        result["state_after"] = self.state
        return result

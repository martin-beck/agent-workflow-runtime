#!/usr/bin/env python3
"""Deterministic, non-executing OpenDesk live-adapter lifecycle harness."""

import hashlib
import json
import re
from dataclasses import dataclass, field

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^[A-Z][A-Z0-9-]{2,31}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
CAPABILITIES = ("conversation", "streaming", "structured_output", "tool_use")


class AdapterError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value) if not isinstance(value, bytes) else value).hexdigest()


def _check_digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise AdapterError("digest reference required")


@dataclass
class OpenDeskLiveHarness:
    task_revision: int = 3
    capabilities: tuple = ("conversation",)
    state: str = "undiscovered"
    binding: dict | None = None
    negotiated: tuple = ()
    operations: set = field(default_factory=set)
    sequence: int = 0
    events: list = field(default_factory=list)

    def _event(self, operation, before, after, disposition, **extra):
        self.sequence += 1
        event = {"sequence": self.sequence, "operation": operation,
                 "state_before": before, "state_after": after,
                 "disposition": disposition, **self.binding, **extra}
        event["event_digest"] = digest(event)
        self.events.append(event)
        self.state = after
        return event

    def discover(self):
        if self.state != "undiscovered":
            raise AdapterError("discovery is single-use")
        if not self.capabilities or len(set(self.capabilities)) != len(self.capabilities) or any(c not in CAPABILITIES for c in self.capabilities):
            raise AdapterError("invalid capability advertisement")
        return self._event("discover", self.state, "discovered", "capabilities_reported",
                           adapter={"id": "opendesk-live", "version": "1.0.0"},
                           capabilities=list(self.capabilities), execute=False)

    def negotiate(self, requested):
        if self.state != "discovered" or not isinstance(requested, list) or not requested or len(set(requested)) != len(requested):
            raise AdapterError("negotiation requires discovery and bounded capabilities")
        if any(capability not in CAPABILITIES for capability in requested):
            raise AdapterError("unknown capability")
        supported = tuple(capability for capability in requested if capability in self.capabilities)
        if not supported:
            raise AdapterError("no compatible capability")
        self.negotiated = supported
        return self._event("negotiate", self.state, "negotiated", "accepted",
                           adapter={"id": "opendesk-live", "version": "1.0.0"},
                           requested_capabilities=requested, negotiated_capabilities=list(supported), execute=False)

    def start(self, task, session):
        if self.state != "negotiated" or task != {"id": "AR-0035", "revision": self.task_revision}:
            raise AdapterError("exact task revision and negotiated lifecycle required")
        if (not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"}
                or not SESSION.fullmatch(str(session["id"]))
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session["worktree_key"]))
                or not DIGEST.fullmatch(str(session["worktree_digest"]))):
            raise AdapterError("invalid session binding")
        self.binding = {"task": task, "session": session, "adapter": {"id": "opendesk-live", "version": "1.0.0"}}
        return self._event("start", self.state, "active", "started", execute=False)

    def request(self, operation_id, capability, request_digest):
        if self.state != "active" or not ID.fullmatch(str(operation_id)) or operation_id in self.operations:
            raise AdapterError("request requires active session and unique operation")
        if capability not in self.negotiated:
            raise AdapterError("capability was not negotiated")
        _check_digest(request_digest)
        self.operations.add(operation_id)
        return self._event("request", self.state, "awaiting_response", "sent",
                           operation_id=operation_id, capability=capability,
                           request_digest=request_digest, execute=False)

    def response(self, operation_id, response_digest, status="completed"):
        if self.state != "awaiting_response" or operation_id not in self.operations:
            raise AdapterError("response correlation or lifecycle mismatch")
        _check_digest(response_digest)
        if status not in {"completed", "failed"}:
            raise AdapterError("bounded response status required")
        return self._event("response", self.state, "active" if status == "completed" else "failed", status,
                           operation_id=operation_id, response_digest=response_digest, execute=False)

    def interrupt(self, checkpoint_digest):
        if self.state not in {"active", "awaiting_response"}:
            raise AdapterError("interrupt requires a live session")
        _check_digest(checkpoint_digest)
        return self._event("interrupt", self.state, "interrupted", "acknowledged",
                           checkpoint_digest=checkpoint_digest, execute=False)

    def resume(self, checkpoint_digest):
        if self.state != "interrupted":
            raise AdapterError("resume requires acknowledged interruption")
        _check_digest(checkpoint_digest)
        return self._event("resume", self.state, "active", "resumed",
                           checkpoint_digest=checkpoint_digest, execute=False)

    def close(self):
        if self.state != "active":
            raise AdapterError("close requires active session")
        return self._event("close", self.state, "completed", "closed", execute=False)

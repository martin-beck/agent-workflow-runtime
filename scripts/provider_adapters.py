#!/usr/bin/env python3
"""Production-shaped provider adapters backed only by deterministic fake transports.

The transport is deliberately an in-memory script.  It has no socket, process,
credential, or LLM seam; the adapter API nevertheless models the boundaries a
live integration must satisfy.
"""

import hashlib
import json
import re
from dataclasses import dataclass


class AdapterError(ValueError):
    """Fail-closed adapter or fake-transport error."""


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUEST = re.compile(r"^REQ-[A-Z0-9-]{1,63}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
CODE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
FORBIDDEN = re.compile(
    r"credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|personal.?data|raw.?output|command|executable",
    re.I,
)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(FORBIDDEN.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)", value, re.I)))


@dataclass(frozen=True)
class ProviderProfile:
    adapter_id: str
    provider: str
    model: str
    capabilities: tuple
    limits: dict
    tools: tuple
    files: tuple


PROFILES = {
    "codex": ProviderProfile("codex", "codex", "codex-offline-1", ("streaming", "tool_use", "file_read", "resume"), {"max_in_flight": 1, "max_stream_frames": 8, "max_request_bytes": 4096}, ("read", "edit", "test"), ("read",)),
    "opencode": ProviderProfile("opencode", "opencode", "opencode-offline-1", ("streaming", "tool_use", "file_read", "file_write", "resume"), {"max_in_flight": 2, "max_stream_frames": 16, "max_request_bytes": 8192}, ("read", "edit", "test"), ("read", "write")),
    "opendesk": ProviderProfile("opendesk", "opendesk", "opendesk-offline-1", ("streaming", "structured_output", "file_read", "resume"), {"max_in_flight": 1, "max_stream_frames": 4, "max_request_bytes": 2048}, ("read",), ("read",)),
}


class FakeTransport:
    """Scripted transport; calling it can never execute a provider."""

    def __init__(self, frames=3):
        self.frames = frames
        self.calls = 0

    def send(self, request_id, request_digest, frame_count):
        self.calls += 1
        if not REQUEST.fullmatch(request_id) or not DIGEST.fullmatch(request_digest):
            raise AdapterError("transport requires bounded correlated identifiers")
        if frame_count < 1:
            raise AdapterError("stream must contain a frame")
        return {"request_id": request_id, "frames": [{"sequence": n, "digest": sha256(canonical_bytes({"request_id": request_id, "frame": n}))} for n in range(1, frame_count + 1)], "status": "complete", "raw_output_absent": True}


class ProductionAdapter:
    """Common lifecycle enforcement used by independently profiled adapters."""

    def __init__(self, profile, transport=None, expected_revision=5):
        if expected_revision != 5 or profile.adapter_id not in PROFILES:
            raise AdapterError("AR-0050 requires Coordinator revision 5")
        self.profile = profile
        self.transport = transport or FakeTransport()
        self.expected_revision = expected_revision
        self.state = "admitted"
        self.binding = None
        self.negotiated = None
        self.requests = {}
        self.checkpoint = None

    def _binding(self, task, session):
        if task != {"id": "AR-0050", "revision": 5} or not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"}:
            raise AdapterError("exact task revision and session binding required")
        if not SESSION.fullmatch(str(session["id"])) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session["worktree_key"])) or not DIGEST.fullmatch(str(session["worktree_digest"])) or not _safe(session):
            raise AdapterError("invalid or private session binding")
        return {"task": dict(task), "session": dict(session), "adapter": {"id": self.profile.adapter_id, "provider": self.profile.provider, "version": "1.0.0"}}

    def discover(self):
        if self.state != "admitted":
            raise AdapterError("discovery is single-use")
        self.state = "discovered"
        return {"operation": "discover", "state": self.state, "adapter": {"id": self.profile.adapter_id, "provider": self.profile.provider, "version": "1.0.0"}, "model": self.profile.model, "model_digest": sha256(self.profile.model.encode())}

    def negotiate(self, task, session, requested):
        if self.state != "discovered" or not isinstance(requested, list) or not requested or len(set(requested)) != len(requested):
            raise AdapterError("capability negotiation requires discovery and a bounded request")
        self.binding = self._binding(task, session)
        if any(capability not in self.profile.capabilities for capability in requested):
            raise AdapterError("unsupported capability negotiation")
        before = self.state
        self.negotiated = tuple(requested)
        self.state = "negotiated"
        return self._event("negotiate", "negotiated", _state_before=before, capabilities=list(requested), limits=self.profile.limits, model=self.profile.model, model_digest=sha256(self.profile.model.encode()))

    def request(self, request_id, request_digest, *, tool=None, file=None):
        if self.state not in {"negotiated", "active", "resumed"} or self.binding is None or not REQUEST.fullmatch(str(request_id)) or not DIGEST.fullmatch(str(request_digest)):
            raise AdapterError("request requires an active negotiated binding")
        if request_id in self.requests:
            raise AdapterError("duplicate request correlation")
        if tool is not None and tool not in self.profile.tools:
            return self._event("request", "tool_denied", request_id=request_id, request_digest=request_digest, execute=False, tool=tool)
        if file is not None and file not in self.profile.files:
            return self._event("request", "file_denied", request_id=request_id, request_digest=request_digest, execute=False, file=file)
        before = self.state
        self.requests[request_id] = request_digest
        self.state = "active"
        return self._event("request", "accepted", _state_before=before, request_id=request_id, request_digest=request_digest, execute=False)

    def stream(self, request_id, frame_count=3):
        if self.state != "active" or request_id not in self.requests:
            raise AdapterError("stream requires the exact outstanding request")
        if frame_count > self.profile.limits["max_stream_frames"]:
            raise AdapterError("provider-specific stream limit exceeded")
        response = self.transport.send(request_id, self.requests[request_id], frame_count)
        return self._event("stream", response["status"], _state_before=self.state, request_id=request_id, frames=response["frames"], redacted=True, raw_output_absent=True)

    def interrupt(self, request_id):
        if self.state != "active" or request_id not in self.requests:
            raise AdapterError("interrupt requires an outstanding request")
        before = self.state
        self.checkpoint = sha256(canonical_bytes({"request_id": request_id, "request_digest": self.requests[request_id]}))
        self.state = "interrupted"
        return self._event("interrupt", "interrupted", _state_before=before, request_id=request_id, checkpoint_digest=self.checkpoint, acknowledged=True)

    def resume(self, request_id, checkpoint_digest):
        if self.state != "interrupted" or request_id not in self.requests or checkpoint_digest != self.checkpoint:
            raise AdapterError("resume requires the exact interruption checkpoint")
        before = self.state
        self.state = "resumed"
        return self._event("resume", "resumed", _state_before=before, request_id=request_id, checkpoint_digest=checkpoint_digest)

    def error(self, request_id, code):
        if self.state not in {"active", "resumed"} or request_id not in self.requests or not CODE.fullmatch(str(code)):
            raise AdapterError("provider error must correlate to an outstanding request")
        before = self.state
        self.state = "failed"
        return self._event("error", "provider_error", _state_before=before, request_id=request_id, error_code=code, success=False)

    def close(self, request_id):
        if self.state not in {"active", "resumed"} or request_id not in self.requests:
            raise AdapterError("close requires the exact outstanding request")
        before = self.state
        self.state = "completed"
        return self._event("close", "completed", _state_before=before, request_id=request_id, success=True)

    def _event(self, operation, disposition, **extra):
        before = extra.pop("_state_before", self.state)
        event = {"sequence": self._next_sequence(), "operation": operation, "state_before": before, "state_after": self.state, "task": self.binding["task"], "session": self.binding["session"], "adapter": self.binding["adapter"], "disposition": disposition, **extra}
        body = dict(event)
        event["evidence_digest"] = sha256(canonical_bytes({"operation": operation, "disposition": disposition, "request_id": extra.get("request_id"), "model": self.profile.model}))
        event["event_digest"] = sha256(canonical_bytes(body))
        return event

    def _next_sequence(self):
        return getattr(self, "_sequence", 0) + 1

    def trace(self):
        return getattr(self, "_trace", [])


def record_event(adapter, event):
    """Append an event for deterministic fixture construction."""
    if not hasattr(adapter, "_trace"):
        adapter._trace = []
    adapter._trace.append(event)
    adapter._sequence = event["sequence"]
    return event


class CodexAdapter(ProductionAdapter):
    def __init__(self, transport=None, expected_revision=5):
        super().__init__(PROFILES["codex"], transport, expected_revision)


class OpenCodeAdapter(ProductionAdapter):
    def __init__(self, transport=None, expected_revision=5):
        super().__init__(PROFILES["opencode"], transport, expected_revision)


class OpenDeskAdapter(ProductionAdapter):
    def __init__(self, transport=None, expected_revision=5):
        super().__init__(PROFILES["opendesk"], transport, expected_revision)


def run_script(adapter):
    """Run the same offline conformance scenario against one independent adapter."""
    adapter.discover()
    record_event(adapter, adapter.negotiate({"id": "AR-0050", "revision": 5}, {"id": "SES-AR0050-OFFLINE", "worktree_key": "agent-workflow-runtime-0050", "worktree_digest": sha256(b"ar0050-worktree")}, list(adapter.profile.capabilities)))
    record_event(adapter, adapter.request("REQ-AR0050-1", sha256(b"request-1"), tool=adapter.profile.tools[0]))
    record_event(adapter, adapter.stream("REQ-AR0050-1"))
    record_event(adapter, adapter.interrupt("REQ-AR0050-1"))
    record_event(adapter, adapter.resume("REQ-AR0050-1", adapter.checkpoint))
    record_event(adapter, adapter.close("REQ-AR0050-1"))
    return adapter.trace()

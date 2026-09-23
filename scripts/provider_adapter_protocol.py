#!/usr/bin/env python3
"""Offline provider-neutral adapter protocol and capability router for AR-0063."""
import hashlib
import json
import re
from dataclasses import dataclass

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_REF = re.compile(r"^secret-ref:[a-z][a-z0-9._-]{0,63}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
CAPABILITIES = ("request", "stream", "tool", "file_read", "file_write", "interrupt", "checkpoint", "resume")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output", re.I)

class ProtocolError(ValueError):
    pass

def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()

def _safe(value):
    if isinstance(value, dict):
        return not any(FORBIDDEN.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|credentials|tmp)(?:[/\\]|$)|BEGIN .* PRIVATE KEY", value, re.I)))

@dataclass(frozen=True)
class CapabilityRouter:
    advertised: tuple
    max_events: int = 64

    def __post_init__(self):
        if not self.advertised or len(self.advertised) > 16 or len(set(self.advertised)) != len(self.advertised) or any(c not in CAPABILITIES for c in self.advertised):
            raise ProtocolError("invalid advertised capabilities")

    def route(self, capability):
        if capability not in CAPABILITIES:
            raise ProtocolError("unknown capability")
        if capability not in self.advertised:
            return {"capability": capability, "disposition": "unsupported", "execute": False, "state_change": False}
        return {"capability": capability, "disposition": "routed", "execute": False, "state_change": False}

class AdapterProtocol:
    """A deterministic, non-executing protocol model. Payloads are digest-only."""
    def __init__(self, advertised=("request", "stream", "interrupt", "checkpoint", "resume"), adapter_id="reference", version="1.0.0", expected_revision=5):
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", adapter_id) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or expected_revision < 1:
            raise ProtocolError("invalid adapter identity")
        self.adapter = {"id": adapter_id, "version": version}
        self.expected_revision = expected_revision
        self.router = CapabilityRouter(tuple(advertised))
        self.state = "new"
        self.binding = None
        self.sequence = 0
        self.checkpoint_digest = None
        self.negotiated = set()

    def _record(self, operation, disposition, state_after=None, **fields):
        if self.sequence >= self.router.max_events:
            raise ProtocolError("event budget exceeded")
        before = self.state
        if state_after is not None:
            self.state = state_after
        self.sequence += 1
        return {"sequence": self.sequence, "operation": operation, "state_before": before, "state_after": self.state, "disposition": disposition, "task": self.binding["task"], "session": self.binding["session"], "adapter": self.adapter, **fields}

    def admit(self, task, session):
        if self.state != "new" or task != {"id": "AR-0063", "revision": self.expected_revision} or not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"} or not SESSION.fullmatch(str(session.get("id", ""))) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session.get("worktree_key", ""))) or not DIGEST.fullmatch(str(session.get("worktree_digest", ""))) or not _safe({"task": task, "session": session}):
            raise ProtocolError("invalid admission binding")
        self.binding = {"task": dict(task), "session": dict(session)}
        return self._record("admission", "admitted", "admitted")

    def discover(self):
        if self.state != "admitted": raise ProtocolError("discovery requires admission")
        body = {"adapter": self.adapter, "capabilities": list(self.router.advertised), "limits": {"max_events": self.router.max_events, "max_chunk_digest": 72}}
        return self._record("discovery", "discovered", "discovered", report={**body, "digest": sha256(canonical_bytes(body))})

    def negotiate(self, requested):
        if self.state != "discovered" or not isinstance(requested, list) or not requested or len(requested) > 16: raise ProtocolError("invalid negotiation")
        routes = [self.router.route(c) for c in requested]
        if any(r["disposition"] == "unsupported" for r in routes):
            return self._record("negotiation", "unsupported", "discovered", routes=routes, state_change=False)
        self.negotiated = set(requested)
        return self._record("negotiation", "negotiated", "ready", routes=routes)

    def request(self, capability, request_digest):
        if self.state not in {"ready", "streaming"} or not DIGEST.fullmatch(str(request_digest)): raise ProtocolError("bounded request required")
        route = self.router.route(capability) if capability in self.negotiated else {"disposition": "unsupported"}
        if route["disposition"] == "unsupported": return self._record("request", "unsupported", self.state, capability=capability, execute=False, state_change=False)
        return self._record("request", "accepted", "active", capability=capability, request_digest=request_digest, execute=False)

    def stream(self, operation, chunk_digest=None):
        if operation == "open" and self.state in {"ready", "active"}: return self._record("stream_open", "accepted", "streaming", execute=False)
        if operation == "chunk" and self.state == "streaming" and DIGEST.fullmatch(str(chunk_digest)): return self._record("stream_chunk", "accepted", "streaming", chunk_digest=chunk_digest, execute=False)
        if operation == "end" and self.state == "streaming": return self._record("stream_end", "accepted", "active", execute=False)
        raise ProtocolError("invalid stream operation")

    def tool_or_file(self, capability, reference):
        if capability not in {"tool", "file_read", "file_write"} or not isinstance(reference, str) or not (DIGEST.fullmatch(reference) or SECRET_REF.fullmatch(reference)):
            raise ProtocolError("tool/file boundary requires digest or secret reference")
        if self.state not in {"ready", "active"}: raise ProtocolError("tool/file requires active negotiation")
        route = self.router.route(capability) if capability in self.negotiated else {"disposition": "unsupported"}
        if route["disposition"] == "unsupported": return self._record(capability, "unsupported", self.state, execute=False, state_change=False)
        return self._record(capability, "accepted", "active", reference=reference, execute=False)

    def interrupt(self):
        if self.state not in {"ready", "active", "streaming"}: raise ProtocolError("cannot interrupt")
        return self._record("interrupt", "acknowledged", "interrupted", execute=False)

    def checkpoint(self, checkpoint_digest):
        if self.state not in {"ready", "active", "interrupted"} or not DIGEST.fullmatch(str(checkpoint_digest)): raise ProtocolError("invalid checkpoint")
        self.checkpoint_digest = checkpoint_digest
        return self._record("checkpoint", "recorded", self.state, checkpoint_digest=checkpoint_digest)

    def resume(self, checkpoint_digest):
        if self.state != "interrupted" or checkpoint_digest != self.checkpoint_digest: raise ProtocolError("checkpoint fence mismatch")
        return self._record("resume", "resumed", "active", checkpoint_digest=checkpoint_digest)

    def fail(self, code):
        if self.state in {"closed", "failed"} or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", str(code)): raise ProtocolError("invalid failure")
        return self._record("failure", "failed", "failed", code=code, execute=False)

    def close(self, reason="completed"):
        if self.state in {"new", "closed", "failed"} or reason not in {"completed", "interrupted", "cancelled"}: raise ProtocolError("invalid close")
        return self._record("close", reason, "closed", execute=False)

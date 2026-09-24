#!/usr/bin/env python3
"""AR-0085 provider-neutral executable adapter sessions.

The session is deliberately a small execution boundary, not an agent or
provider client.  It admits one already validated AR-0084 profile, starts
repository-owned deterministic helper processes through AR-0083, and exposes
bounded normalized events.  The helper emits LiteLLM-shaped *local mock*
envelopes; no prompt, transcript, credential, backend, or network value is
accepted or produced here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from scripts.agent_registry import AgentRegistry, RegistryError
from scripts.local_supervisor import Budget, Lease, LocalSupervisor, SupervisorError

PROTOCOL = {"id": "awr-agent-session", "version": "1.0.0"}
TASK = {"id": "AR-0085", "revision": 3}
SESSION_ID = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WORKTREE_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EVENT_ID = re.compile(r"^EV-[A-Z0-9-]{1,63}$")
RUN_ID = re.compile(r"^RUN-[A-Z0-9-]{1,63}$")
STATES = {"new", "started", "streaming", "interrupted", "closed", "failed"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class AdapterError(ValueError):
    """A normalized, fail-closed session error."""

    def __init__(self, code: str, message: str, *, state: str = "unknown") -> None:
        super().__init__(message)
        self.code = code
        self.state = state

    def public(self, session_id: str | None = None) -> dict[str, object]:
        return {
            "protocol": PROTOCOL,
            "error": self.code,
            "disposition": "blocked",
            "state": self.state,
            "session_id": session_id,
            "execute": False,
        }


def _bounded_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise AdapterError("malformed_digest", f"{name} must be a SHA-256 digest")
    return value


def _json_size(value: object) -> int:
    return len(canonical(value))


@dataclass(frozen=True)
class SessionBinding:
    session_id: str
    worktree_key: str
    worktree_digest: str

    def validate(self) -> SessionBinding:
        if not SESSION_ID.fullmatch(self.session_id):
            raise AdapterError("malformed_session", "session identity is invalid")
        if not WORKTREE_KEY.fullmatch(self.worktree_key):
            raise AdapterError("malformed_worktree", "worktree key is invalid")
        _bounded_digest(self.worktree_digest, "worktree_digest")
        return self

    def public(self) -> dict[str, str]:
        return {
            "id": self.session_id,
            "worktree_key": self.worktree_key,
            "worktree_digest": self.worktree_digest,
        }


class LiteLLMStyleLocalMock:
    """Deterministic local response generator with a familiar envelope shape."""

    @staticmethod
    def envelope(profile_id: str, request_digest: str, ordinal: int, *, stream: bool) -> dict[str, object]:
        suffix = request_digest.removeprefix("sha256:")[:16]
        return {
            "id": f"local-mock-{suffix}-{ordinal}",
            "object": "chat.completion.chunk" if stream else "chat.completion",
            "model": "local-deterministic-mock",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": None if stream else "stop",
                    "delta": {"content": f"mock:{profile_id}:{suffix}:{ordinal}"} if stream else {},
                    "message": {} if stream else {"role": "assistant", "content": f"mock:{profile_id}:{suffix}:{ordinal}"},
                }
            ],
            "usage": {"input_units": 0, "output_units": 0, "total_units": 0},
        }


class AdapterSession:
    """One fenced, supervised, provider-neutral local adapter session."""

    def __init__(
        self,
        registry: AgentRegistry,
        supervisor: LocalSupervisor,
        *,
        profile_id: str,
        binding: SessionBinding,
        lease: Lease,
        helper: Path,
        executable: Path | None = None,
        task: dict[str, object] | None = None,
        clock=time.monotonic,
    ) -> None:
        self.registry = registry
        self.supervisor = supervisor
        self.profile = self._profile(profile_id)
        self.binding = binding.validate()
        self.lease = lease.validate()
        self.helper = helper.resolve(strict=True)
        self.executable = (executable or Path(sys.executable)).resolve(strict=True)
        self.task = dict(task or TASK)
        if self.task != TASK:
            raise AdapterError("stale_task", "session task revision is stale")
        self.clock = clock
        self.state = "new"
        self.sequence = 0
        self.previous_event: str | None = None
        self.events: list[dict[str, object]] = []
        self._active_handle = None
        self._checkpoint_digest: str | None = None

    def _profile(self, profile_id: str) -> dict[str, object]:
        try:
            return self.registry.profile(profile_id)
        except RegistryError as exc:
            raise AdapterError("unknown_profile", "agent profile is not registered") from exc

    def _guard_lease(self, lease: Lease | None) -> None:
        supplied = lease or self.lease
        try:
            supplied.validate()
        except SupervisorError as exc:
            raise AdapterError("malformed_lease", "lease is invalid", state=self.state) from exc
        if supplied.worker_id != self.lease.worker_id or supplied.lease_id != self.lease.lease_id:
            raise AdapterError("stale_lease", "session lease fence mismatch", state=self.state)
        if self.clock() >= self.lease.expires_at:
            raise AdapterError("expired_lease", "session lease has expired", state=self.state)

    def _require_state(self, *allowed: str) -> None:
        if self.state not in allowed:
            raise AdapterError("invalid_state", f"operation is not valid in {self.state}", state=self.state)

    def _require_capability(self, capability: str) -> None:
        if capability not in self.profile["capabilities"]:
            raise AdapterError("capability_mismatch", f"profile does not support {capability}", state=self.state)

    def _request_digest(self, request_digest: str) -> str:
        if isinstance(request_digest, str) and len(request_digest.encode()) > int(self.profile["resources"]["max_request_bytes"]):
            raise AdapterError("payload_too_large", "request digest exceeds profile limit", state=self.state)
        value = _bounded_digest(request_digest, "request_digest")
        limit = int(self.profile["resources"]["max_request_bytes"])
        if len(value.encode()) > limit:
            raise AdapterError("payload_too_large", "request digest exceeds profile limit", state=self.state)
        return value

    def _run_id(self, operation: str) -> str:
        candidate = f"RUN-0085-{self.binding.session_id.removeprefix('SES-')}-{self.sequence + 1}-{operation.upper()}"
        candidate = re.sub(r"[^A-Z0-9-]", "-", candidate)
        if not RUN_ID.fullmatch(candidate):
            raise AdapterError("run_identity", "bounded run identity could not be created", state=self.state)
        return candidate

    def _command(self, mode: str, request_digest: str, ordinal: int = 0) -> list[str]:
        return [
            str(self.executable),
            str(self.helper),
            mode,
            str(self.profile["id"]),
            request_digest,
            str(ordinal),
        ]

    def _execute(self, mode: str, request_digest: str, *, ordinal: int = 0, interrupt: bool = False) -> dict[str, object]:
        budget = Budget(
            timeout_ms=2_000 if not interrupt else 5_000,
            output_bytes=min(16 * 1024, int(self.profile["resources"]["max_request_bytes"]) * 8),
        )
        try:
            if interrupt:
                handle = self.supervisor.launch(
                    self._run_id(mode),
                    self._command(mode, request_digest, ordinal),
                    lease=self.lease,
                    budget=budget,
                )
                self._active_handle = handle
                result = handle.cancel(self.lease, now=self.clock())
            else:
                result = self.supervisor.run(
                    self._run_id(mode),
                    self._command(mode, request_digest, ordinal),
                    lease=self.lease,
                    budget=budget,
                )
        except SupervisorError as exc:
            raise AdapterError("supervisor_failure", "supervised local operation failed", state=self.state) from exc
        finally:
            self._active_handle = None
        if result.disposition != ("cancelled" if interrupt else "completed"):
            raise AdapterError("supervisor_failure", "local operation did not complete", state=self.state)
        if len(result.stdout.encode()) > budget.output_bytes:
            raise AdapterError("payload_too_large", "local result exceeded output bound", state=self.state)
        if interrupt:
            return {"disposition": result.disposition, "lease_id": result.lease_id}
        try:
            value = json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            raise AdapterError("malformed_mock", "local mock envelope is not JSON", state=self.state) from exc
        if not isinstance(value, dict) or value.get("model") != "local-deterministic-mock":
            raise AdapterError("malformed_mock", "local mock envelope is not normalized", state=self.state)
        return value

    def _emit(self, event_type: str, disposition: str, details: dict[str, object] | None = None) -> dict[str, object]:
        maximum = int(self.profile["resources"]["max_output_events"])
        if self.sequence >= maximum:
            raise AdapterError("event_limit", "profile event budget exhausted", state=self.state)
        self.sequence += 1
        event_id = f"EV-{self.binding.session_id.removeprefix('SES-')}-{self.sequence}"
        payload = details or {}
        if _json_size(payload) > int(self.profile["resources"]["max_request_bytes"]) * 2:
            raise AdapterError("payload_too_large", "event payload exceeds bound", state=self.state)
        event: dict[str, object] = {
            "schema_version": 1,
            "protocol": PROTOCOL,
            "event_id": event_id,
            "sequence": self.sequence,
            "event_type": event_type,
            "task": dict(self.task),
            "session": self.binding.public(),
            "adapter": {"id": self.profile["adapter_id"], "version": self.profile["adapter_version"]},
            "correlation": {"session_id": self.binding.session_id, "parent_event_id": self.previous_event},
            "disposition": disposition,
            "details": payload,
            "evidence_digest": digest(payload),
        }
        event["event_digest"] = digest(event)
        self.previous_event = event_id
        self.events.append(event)
        return event

    def start(self, *, lease: Lease | None = None) -> dict[str, object]:
        self._guard_lease(lease)
        self._require_state("new")
        result = self._execute("start", digest({"session": self.binding.public(), "profile": self.profile["id"]}), ordinal=0)
        self.state = "started"
        return self._emit("session_started", "started", {"response_digest": digest(result), "local_mock": True})

    def request(self, request_digest: str, *, capability: str = "read", lease: Lease | None = None) -> dict[str, object]:
        self._guard_lease(lease)
        self._require_state("started")
        self._require_capability(capability)
        request_digest = self._request_digest(request_digest)
        result = self._execute("request", request_digest)
        return self._emit("request_accepted", "accepted", {"request_digest": request_digest, "response": result})

    def stream(self, request_digest: str, *, count: int = 2, lease: Lease | None = None) -> list[dict[str, object]]:
        self._guard_lease(lease)
        self._require_state("started")
        self._require_capability("streaming")
        request_digest = self._request_digest(request_digest)
        maximum = int(self.profile["resources"]["max_output_events"])
        if isinstance(count, bool) or not isinstance(count, int) or count < 1 or count > maximum - self.sequence:
            raise AdapterError("event_limit", "stream count exceeds profile event budget", state=self.state)
        self.state = "streaming"
        events: list[dict[str, object]] = []
        try:
            for ordinal in range(1, count + 1):
                result = self._execute("stream", request_digest, ordinal=ordinal)
                events.append(self._emit("stream_chunk", "accepted", {"request_digest": request_digest, "response": result}))
        finally:
            if self.state == "streaming":
                self.state = "started"
        return events

    def interrupt(self, request_digest: str, *, lease: Lease | None = None) -> dict[str, object]:
        self._guard_lease(lease)
        self._require_state("started")
        request_digest = self._request_digest(request_digest)
        self._execute("interrupt", request_digest, interrupt=True)
        self._checkpoint_digest = digest({"session": self.binding.session_id, "request": request_digest, "sequence": self.sequence})
        self.state = "interrupted"
        return self._emit("interrupted", "cancelled", {"checkpoint_digest": self._checkpoint_digest})

    def resume(self, checkpoint_digest: str, *, lease: Lease | None = None) -> dict[str, object]:
        self._guard_lease(lease)
        self._require_state("interrupted")
        checkpoint_digest = _bounded_digest(checkpoint_digest, "checkpoint_digest")
        if checkpoint_digest != self._checkpoint_digest:
            raise AdapterError("fence_mismatch", "checkpoint does not belong to this interruption", state=self.state)
        result = self._execute("resume", checkpoint_digest)
        self.state = "started"
        return self._emit("resumed", "accepted", {"checkpoint_digest": checkpoint_digest, "response_digest": digest(result)})

    def close(self, *, lease: Lease | None = None) -> dict[str, object]:
        self._guard_lease(lease)
        self._require_state("started", "interrupted")
        result = self._execute("close", digest({"session": self.binding.session_id, "state": self.state}))
        self.state = "closed"
        return self._emit("closed", "completed", {"response_digest": digest(result)})


def load_registry(spec_path: Path) -> AgentRegistry:
    try:
        return AgentRegistry(json.loads(spec_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, RegistryError) as exc:
        raise AdapterError("registry_failure", "agent registry could not be loaded") from exc


__all__ = [
    "PROTOCOL",
    "AdapterError",
    "AdapterSession",
    "LiteLLMStyleLocalMock",
    "SessionBinding",
    "canonical",
    "digest",
    "load_registry",
]

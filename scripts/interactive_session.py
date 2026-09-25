"""Bounded provider-neutral interaction and replay for AR-0132 sessions."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable


class InteractionError(ValueError):
    """A stale, malformed, unbounded, or out-of-turn interaction."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _redact(text: str) -> str:
    text = re.sub(r"(?i)\b(token|password|secret|credential)\s*[:=]\s*[^\s,;]+", r"\1=REDACTED", text)
    return re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer REDACTED", text)


@dataclass(frozen=True)
class InteractionBinding:
    session_id: str
    task_revision: int
    lease_id: str
    lease_fence: int


class InteractiveSession:
    """Normalize native frames from an already admitted AR-0131 session."""

    MAX_FRAME = 4096
    MAX_PROMPT = 2048
    MAX_EVENTS = 64
    PROTOCOLS = {"fake-alpha", "fake-beta"}

    def __init__(self, binding: InteractionBinding, *, protocol: str, lease_expires_at: float,
                 clock=time.time, queue_limit: int = 16):
        if protocol not in self.PROTOCOLS:
            raise InteractionError("protocol_unsupported")
        if (not re.fullmatch(r"SES-[A-Z0-9-]{3,64}", binding.session_id)
                or isinstance(binding.task_revision, bool) or not isinstance(binding.task_revision, int) or binding.task_revision < 1
                or isinstance(binding.lease_fence, bool) or not isinstance(binding.lease_fence, int) or binding.lease_fence < 1
                or not re.fullmatch(r"LSE-[A-Z0-9-]{1,63}", binding.lease_id)
                or not isinstance(lease_expires_at, (int, float)) or isinstance(lease_expires_at, bool)
                or not math.isfinite(lease_expires_at)):
            raise InteractionError("binding_invalid")
        if not 1 <= queue_limit <= self.MAX_EVENTS:
            raise InteractionError("backpressure_limit_invalid")
        self.binding, self.protocol, self.lease_expires_at = binding, protocol, lease_expires_at
        self.clock, self.queue_limit = clock, queue_limit
        self.sequence = 0
        self.correlation = 0
        self.pending: int | None = None
        self.pending_correlation: str | None = None
        self.pending_deadline: float | None = None
        self.terminal = False
        self.cancelling = False
        self.cancel_operation: str | None = None
        self.events: list[dict[str, Any]] = []
        self._outstanding = 0

    def input(self, envelope: dict[str, Any], *, session_id: str | None = None) -> dict[str, Any]:
        self._fence()
        required = {"session_id", "task_revision", "lease_id", "lease_fence", "correlation_id", "prompt", "deadline"}
        if not isinstance(envelope, dict) or set(envelope) != required:
            raise InteractionError("input_shape_invalid")
        if session_id is not None and session_id != self.binding.session_id:
            raise InteractionError("cross_session_input")
        if any(envelope[k] != v for k, v in (("session_id", self.binding.session_id), ("task_revision", self.binding.task_revision), ("lease_id", self.binding.lease_id), ("lease_fence", self.binding.lease_fence))):
            raise InteractionError("stale_binding")
        prompt = envelope["prompt"]
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt.encode()) > self.MAX_PROMPT:
            raise InteractionError("prompt_invalid_or_oversized")
        deadline = envelope["deadline"]
        if not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not math.isfinite(deadline) or deadline <= self.clock() or deadline > self.lease_expires_at:
            raise InteractionError("deadline_invalid")
        if self.terminal:
            raise InteractionError("session_terminal")
        if self.pending is not None:
            raise InteractionError("turn_already_pending")
        corr = envelope["correlation_id"]
        if not isinstance(corr, str) or not re.fullmatch(r"COR-[A-Z0-9-]{1,48}", corr):
            raise InteractionError("correlation_invalid")
        self.correlation += 1
        self.pending = self.correlation
        self.pending_correlation = corr
        self.pending_deadline = float(deadline)
        self._outstanding = 0
        return {"session_id": self.binding.session_id, "correlation_id": corr, "turn": self.pending, "prompt": prompt}

    def feed(self, stream: str, native_frame: bytes | str, *, session_id: str | None = None) -> dict[str, Any]:
        self._fence()
        if self.terminal or self.pending is None:
            raise InteractionError("unsolicited_output")
        if self.pending_deadline is None or self.clock() >= self.pending_deadline:
            raise InteractionError("turn_deadline_expired")
        if session_id is not None and session_id != self.binding.session_id:
            raise InteractionError("cross_session_output")
        raw = native_frame.encode() if isinstance(native_frame, str) else native_frame
        if not isinstance(raw, bytes) or len(raw) > self.MAX_FRAME:
            raise InteractionError("frame_too_large")
        if stream not in {"stdout", "stderr"}:
            raise InteractionError("stream_invalid")
        self._outstanding += 1
        if self._outstanding > self.queue_limit:
            raise InteractionError("backpressure_exceeded")
        try:
            value = json.loads(raw)
            if self.protocol == "fake-alpha":
                kind, body = value["type"], value["data"]
            else:
                kind, body = value["event"], value["payload"]
            if not isinstance(kind, str) or not isinstance(body, dict):
                raise ValueError
            normalized = self._normalize(kind, body, stream)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise InteractionError("native_event_malformed") from exc
        normalized.update({"correlation_id": self.pending_correlation, "turn": self.pending})
        return self._append(normalized)

    def end_turn(self, correlation_id: str) -> dict[str, Any]:
        self._fence()
        if self.pending is None:
            raise InteractionError("unsolicited_end_turn")
        if correlation_id != self.pending_correlation:
            raise InteractionError("correlation_mismatch")
        event = self._append({"kind": "end_turn", "correlation_id": correlation_id, "turn": self.pending})
        self.pending = None
        self.pending_correlation = None
        self.pending_deadline = None
        self._outstanding = 0
        return event

    def close(self, status: str = "completed") -> dict[str, Any]:
        self._fence()
        if self.pending is not None or status not in {"completed", "failed", "cancelled", "timed_out"}:
            raise InteractionError("terminal_transition_invalid")
        self.terminal = True
        return self._append({"kind": "terminal", "status": status})

    def request_cancel(self, operation_id: str) -> dict[str, Any]:
        """Fence new input/output immediately while awaiting process cleanup."""
        self._fence(allow_cancelling=True)
        if not isinstance(operation_id, str) or not re.fullmatch(r"OP-[A-Z0-9-]{1,63}", operation_id):
            raise InteractionError("cancel_operation_invalid")
        if self.terminal:
            raise InteractionError("session_terminal")
        if self.cancelling:
            if operation_id != self.cancel_operation:
                raise InteractionError("cancel_operation_conflict")
            return {"status": "cancelling", "operation_id": operation_id}
        self.cancelling, self.cancel_operation = True, operation_id
        self.pending = None
        self.pending_correlation = None
        self.pending_deadline = None
        return {"status": "cancelling", "operation_id": operation_id}

    def acknowledge_cancel(self, operation_id: str, *, process_group_clean: bool) -> dict[str, Any]:
        self._fence(allow_cancelling=True)
        if self.terminal:
            raise InteractionError("session_terminal")
        if not self.cancelling or operation_id != self.cancel_operation:
            raise InteractionError("cancel_ack_unmatched")
        if process_group_clean is not True:
            raise InteractionError("cancel_cleanup_unconfirmed")
        self.terminal = True
        return self._append({"kind": "terminal", "status": "cancelled", "cancel_operation": operation_id,
                             "process_group_clean": True})

    def _normalize(self, kind: str, body: dict[str, Any], stream: str) -> dict[str, Any]:
        mapping = ({"message": "assistant", "call": "tool", "state": "status"} if self.protocol == "fake-alpha" else {"assistant_delta": "assistant", "tool_invocation": "tool", "lifecycle": "status"})
        if kind not in mapping or set(body) - {"text", "name", "state"}:
            raise InteractionError("native_event_malformed")
        normalized_kind = mapping[kind]
        field = {"assistant": "text", "tool": "name", "status": "state"}[normalized_kind]
        content = body.get(field)
        if not isinstance(content, str) or not content or len(content.encode()) > self.MAX_FRAME:
            raise InteractionError("native_event_malformed")
        return {"kind": normalized_kind, "stream": stream, field: _redact(content)}

    def _append(self, event: dict[str, Any]) -> dict[str, Any]:
        if len(self.events) >= self.MAX_EVENTS:
            raise InteractionError("event_limit_exceeded")
        self.sequence += 1
        value = {"sequence": self.sequence, "session_id": self.binding.session_id,
                 "task_revision": self.binding.task_revision, "lease_id": self.binding.lease_id,
                 "lease_fence": self.binding.lease_fence, **event}
        value["event_digest"] = _digest(value)
        self.events.append(value)
        return value

    def _fence(self, *, allow_cancelling: bool = False) -> None:
        if self.clock() >= self.lease_expires_at:
            raise InteractionError("lease_stale")
        if self.cancelling and not allow_cancelling:
            raise InteractionError("session_cancelling")


def replay(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Verify and reproduce a privacy-safe normalized event stream."""
    result = []
    for expected, event in enumerate(events, 1):
        if not isinstance(event, dict) or event.get("sequence") != expected:
            raise InteractionError("replay_sequence_invalid")
        if event.get("kind") not in {"assistant", "tool", "status", "end_turn", "terminal"}:
            raise InteractionError("replay_event_invalid")
        if not re.fullmatch(r"SES-[A-Z0-9-]{3,64}", str(event.get("session_id", ""))) or not isinstance(event.get("task_revision"), int) or isinstance(event.get("task_revision"), bool) or event["task_revision"] < 1:
            raise InteractionError("replay_binding_invalid")
        if event["kind"] in {"assistant", "tool", "status"} and event.get("stream") not in {"stdout", "stderr"}:
            raise InteractionError("replay_event_invalid")
        unsigned = {k: v for k, v in event.items() if k != "event_digest"}
        if event.get("event_digest") != _digest(unsigned):
            raise InteractionError("replay_digest_invalid")
        if result and result[-1]["kind"] == "terminal":
            raise InteractionError("replay_terminal_followup")
        if any(re.search(r"(?i)(password|token|secret|credential)\s*[:=](?!REDACTED)", str(v)) for v in event.values()):
            raise InteractionError("replay_private_value")
        result.append(dict(event))
    return result


__all__ = ["InteractionBinding", "InteractionError", "InteractiveSession", "replay"]

"""Bounded hosted-shaped transport for authority observations.

The transport is deliberately authority-neutral: a server supplies an
observation and the runtime only validates its binding and projects it.  The
fake server in this module is deterministic and is used by tests; no network
client or hosted-success claim is provided here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from scripts.local_authority_bridge import (
    AuthorityBridgeError,
    AMBIGUOUS,
    PROTOCOL,
    digest,
    validate_exchange,
)

# Keep transport failures distinct from authority outcomes.  A timeout before
# a response is retryable; an unknown response is not safe to retry because it
# may represent a committed authority write.
RETRYABLE_TRANSPORT = {"unavailable", "reset", "deadline"}


class HostedTransportError(AuthorityBridgeError):
    """A bounded transport or observation validation failure."""


class AmbiguousAuthorityOutcome(HostedTransportError):
    """The authority did not establish whether the operation committed."""


@dataclass(frozen=True)
class HostedExchange:
    response: dict[str, Any]
    correlation_id: str
    attempt: int
    deadline_ms: int


@dataclass
class DeterministicHostedServer:
    """A deterministic fake hosted endpoint used by conformance tests."""

    authority: str
    outcomes: list[str]
    failures: list[str] = field(default_factory=list)
    delay_ms: int = 0
    requests: list[dict[str, Any]] = field(default_factory=list)
    _responses: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __call__(self, envelope: dict[str, Any]) -> HostedExchange:
        request = envelope["request"]
        correlation_id = envelope["correlation_id"]
        self.requests.append(envelope)
        if request["authority"] != self.authority:
            raise HostedTransportError("endpoint authority mismatch")
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000)
        failure = self.failures.pop(0) if self.failures else None
        if failure:
            raise HostedTransportError("transport " + failure)
        if correlation_id in self._responses:
            response = self._responses[correlation_id]
        else:
            outcome = self.outcomes.pop(0) if self.outcomes else "unknown"
            response = {
                "protocol": dict(PROTOCOL),
                "authority": self.authority,
                "operation_id": request.get("operation_id"),
                "task_id": request.get("task_id"),
                "task_revision": request.get("task_revision"),
                "request_digest": digest(request),
                "outcome": outcome,
            }
            if outcome not in {"unknown", "ambiguous", "indeterminate"}:
                self._responses[correlation_id] = response
        return HostedExchange(
            response=response,
            correlation_id=correlation_id,
            attempt=envelope["attempt"],
            deadline_ms=envelope["deadline_ms"],
        )


@dataclass
class HostedAuthorityClient:
    """Transport and observation adapter over the existing authority contract."""

    endpoints: dict[str, Callable[[dict[str, Any]], HostedExchange]]
    max_attempts: int = 3
    deadline_ms: int = 250

    def exchange(self, request: dict[str, Any], *, expected_revision: int, required_authority: str) -> dict[str, Any]:
        self._check_bounds()
        if required_authority not in self.endpoints or request.get("authority") != required_authority:
            raise HostedTransportError("required hosted authority unavailable")
        if request.get("task_revision") != expected_revision:
            raise HostedTransportError("stale task revision")
        operation_id = request.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            raise HostedTransportError("missing correlation id")
        endpoint = self.endpoints[required_authority]
        started = time.monotonic()
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            elapsed_ms = int((time.monotonic() - started) * 1000)
            remaining_ms = self.deadline_ms - elapsed_ms
            if remaining_ms <= 0:
                raise HostedTransportError("deadline exceeded") from last_error
            envelope = {
                "protocol": dict(PROTOCOL),
                "authority": required_authority,
                "correlation_id": operation_id,
                "attempt": attempt,
                "deadline_ms": remaining_ms,
                "request": request,
            }
            try:
                exchange = endpoint(envelope)
                if (time.monotonic() - started) * 1000 > self.deadline_ms:
                    raise HostedTransportError("deadline exceeded")
                if exchange.correlation_id != operation_id:
                    raise HostedTransportError("correlation mismatch")
                if exchange.attempt != attempt:
                    raise HostedTransportError("attempt mismatch")
                if exchange.deadline_ms < 0:
                    raise HostedTransportError("invalid deadline metadata")
                response = exchange.response
                if response.get("outcome") in AMBIGUOUS:
                    raise AmbiguousAuthorityOutcome("ambiguous authority outcome")
                return validate_exchange(
                    request,
                    response,
                    expected_revision=expected_revision,
                    required_authorities={required_authority},
                )
            except AmbiguousAuthorityOutcome:
                raise
            except HostedTransportError as error:
                last_error = error
                if not str(error).startswith("transport "):
                    raise
                if str(error).split(" ", 1)[1] not in RETRYABLE_TRANSPORT:
                    raise
        raise HostedTransportError("retry budget exhausted") from last_error

    def _check_bounds(self) -> None:
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 5:
            raise HostedTransportError("invalid attempt bound")
        if type(self.deadline_ms) is not int or not 1 <= self.deadline_ms <= 10_000:
            raise HostedTransportError("invalid deadline bound")

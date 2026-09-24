#!/usr/bin/env python3
"""Bounded, provider-neutral Coordinator client and deterministic in-process fake.

This module deliberately has no socket, filesystem, subprocess, network, or
credential handling.  A production transport can implement ``BoundedTransport``
later; the client remains the boundary that validates bindings, retries only
safe transport failures, and never turns an ambiguous write into success.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

PROTOCOL = {"id": "awr-coordinator-client", "version": "1.0.0"}
MAX_ATTEMPTS = 3
MAX_TIMEOUT_MS = 30_000
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PATTERNS = {
    "task_id": re.compile(r"^AR-[0-9]{4}$"),
    "session_id": re.compile(r"^SES-[A-Z0-9-]{1,63}$"),
    "owner_id": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"),
    "lease_id": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
    "operation_id": re.compile(r"^OP-[A-Z0-9-]{1,63}$"),
    "correlation_id": re.compile(r"^CORR-[A-Z0-9-]{1,63}$"),
    "auth_reference": re.compile(r"^AUTH-[A-Z0-9-]{1,63}$"),
}
PRIVATE = re.compile(
    r"(?:credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|raw.?output)",
    re.IGNORECASE,
)
PRIVATE_VALUE = re.compile(
    r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|"
    r"BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]",
    re.IGNORECASE,
)


class CoordinatorClientError(ValueError):
    """Base class for fail-closed client and fake protocol errors."""


class CoordinatorRejected(CoordinatorClientError):
    """Coordinator rejected a request; retrying it cannot make it valid."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class UnknownOutcome(CoordinatorClientError):
    """A write may have committed, but its outcome was not observed."""

    def __init__(self, operation_id: str, correlation_id: str):
        super().__init__("unknown_outcome")
        self.operation_id = operation_id
        self.correlation_id = correlation_id


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _private(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            PRIVATE.search(str(key)) or _private(item) for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_private(item) for item in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


def _id(name: str, value: Any) -> str:
    if not isinstance(value, str) or not PATTERNS[name].fullmatch(value):
        raise CoordinatorClientError(f"invalid_{name}")
    return value


@dataclass(frozen=True)
class CoordinatorBinding:
    task_id: str
    project_key: str
    worktree_key: str
    session_id: str
    owner_id: str
    lease_id: str
    auth_reference: str

    def validate(self) -> None:
        _id("task_id", self.task_id)
        if self.project_key != "agent-workflow-runtime" or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,63}", self.project_key
        ):
            raise CoordinatorClientError("invalid_project_key")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", self.worktree_key):
            raise CoordinatorClientError("invalid_worktree_key")
        for name in ("session_id", "owner_id", "lease_id", "auth_reference"):
            _id(name, getattr(self, name))

    def as_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "task_id": self.task_id,
            "project_key": self.project_key,
            "worktree_key": self.worktree_key,
            "session_id": self.session_id,
            "owner_id": self.owner_id,
            "lease_id": self.lease_id,
            "auth_reference": self.auth_reference,
        }


@dataclass(frozen=True)
class RevisionSnapshot:
    task_id: str
    revision: int
    event_count: int
    state_digest: str
    correlation_id: str
    operation_id: str


@dataclass(frozen=True)
class CasWrite:
    task_id: str
    revision: int
    event_count: int
    event_digest: str
    correlation_id: str
    operation_id: str


class BoundedTransport(Protocol):
    def exchange(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Exchange one already-bounded request; no transport is implied here."""


class CoordinatorClient:
    """Typed Coordinator client over a bounded request/response transport."""

    def __init__(
        self,
        transport: BoundedTransport,
        binding: CoordinatorBinding,
        *,
        max_attempts: int = 3,
    ):
        if max_attempts not in range(1, MAX_ATTEMPTS + 1):
            raise CoordinatorClientError("invalid_retry_bound")
        binding.validate()
        self.transport = transport
        self.binding = binding
        self.max_attempts = max_attempts

    def read_revision(
        self,
        operation_id: str,
        correlation_id: str,
        *,
        expected_revision: int,
        timeout_ms: int = 1000,
    ) -> RevisionSnapshot:
        response = self._call(
            "read_revision",
            operation_id,
            correlation_id,
            expected_revision,
            timeout_ms=timeout_ms,
        )
        return self._read_response(response, correlation_id, operation_id)

    def write_event(
        self,
        operation_id: str,
        correlation_id: str,
        *,
        expected_revision: int,
        event_kind: str,
        event_digest: str,
        timeout_ms: int = 1000,
    ) -> CasWrite:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", event_kind):
            raise CoordinatorClientError("invalid_event_kind")
        if not DIGEST.fullmatch(event_digest):
            raise CoordinatorClientError("invalid_event_digest")
        response = self._call(
            "write_event",
            operation_id,
            correlation_id,
            expected_revision,
            event_kind=event_kind,
            event_digest=event_digest,
            timeout_ms=timeout_ms,
        )
        return self._write_response(
            response, correlation_id, operation_id, event_digest
        )

    def _call(
        self,
        operation: str,
        operation_id: str,
        correlation_id: str,
        expected_revision: int,
        *,
        timeout_ms: int,
        event_kind: str | None = None,
        event_digest: str | None = None,
    ) -> Mapping[str, Any]:
        _id("operation_id", operation_id)
        _id("correlation_id", correlation_id)
        if operation not in {"read_revision", "write_event"}:
            raise CoordinatorClientError("unknown_operation")
        if not isinstance(expected_revision, int) or expected_revision < 1:
            raise CoordinatorClientError("invalid_expected_revision")
        if timeout_ms not in range(1, MAX_TIMEOUT_MS + 1):
            raise CoordinatorClientError("invalid_timeout")
        request: dict[str, Any] = {
            "protocol": PROTOCOL,
            **self.binding.as_dict(),
            "operation": operation,
            "operation_id": operation_id,
            "correlation_id": correlation_id,
            "expected_revision": expected_revision,
            "timeout_ms": timeout_ms,
        }
        if event_kind is not None:
            request["event_kind"] = event_kind
        if event_digest is not None:
            request["event_digest"] = event_digest
        request["auth_proof_digest"] = digest(
            {
                "auth_reference": self.binding.auth_reference,
                "correlation_id": correlation_id,
            }
        )
        retryable = {"unavailable", "deadline_exceeded", "timeout"}
        for attempt in range(1, self.max_attempts + 1):
            request["attempt"] = attempt
            try:
                response = self.transport.exchange(request)
                if not isinstance(response, Mapping):
                    raise CoordinatorClientError("malformed_response")
                return response
            except CoordinatorRejected as exc:
                if exc.code == "ambiguous_outcome":
                    raise UnknownOutcome(operation_id, correlation_id) from exc
                if exc.code in retryable and attempt < self.max_attempts:
                    continue
                raise

        raise CoordinatorClientError("retry_exhausted")

    @staticmethod
    def _common_response(
        response: Mapping[str, Any], correlation_id: str, operation_id: str
    ) -> None:
        if response.get("disposition") != "accepted":
            raise CoordinatorClientError("malformed_response")
        if (
            response.get("correlation_id") != correlation_id
            or response.get("operation_id") != operation_id
        ):
            raise CoordinatorClientError("response_correlation_mismatch")
        if (
            not isinstance(response.get("task_revision"), int)
            or response["task_revision"] < 1
        ):
            raise CoordinatorClientError("malformed_response")
        if (
            not isinstance(response.get("event_count"), int)
            or response["event_count"] < 0
        ):
            raise CoordinatorClientError("malformed_response")

    @classmethod
    def _read_response(
        cls, response: Mapping[str, Any], correlation_id: str, operation_id: str
    ) -> RevisionSnapshot:
        cls._common_response(response, correlation_id, operation_id)
        if not isinstance(response.get("task_id"), str) or not PATTERNS[
            "task_id"
        ].fullmatch(response["task_id"]):
            raise CoordinatorClientError("malformed_response")
        state_digest = response.get("state_digest")
        if not isinstance(state_digest, str) or not DIGEST.fullmatch(state_digest):
            raise CoordinatorClientError("malformed_response")
        return RevisionSnapshot(
            response["task_id"],
            response["task_revision"],
            response["event_count"],
            state_digest,
            correlation_id,
            operation_id,
        )

    @classmethod
    def _write_response(
        cls,
        response: Mapping[str, Any],
        correlation_id: str,
        operation_id: str,
        expected_digest: str,
    ) -> CasWrite:
        cls._common_response(response, correlation_id, operation_id)
        if not isinstance(response.get("task_id"), str) or not PATTERNS[
            "task_id"
        ].fullmatch(response["task_id"]):
            raise CoordinatorClientError("malformed_response")
        event_digest = response.get("event_digest")
        if event_digest != expected_digest or not DIGEST.fullmatch(str(event_digest)):
            raise CoordinatorClientError("response_event_mismatch")
        return CasWrite(
            response["task_id"],
            response["task_revision"],
            response["event_count"],
            event_digest,
            correlation_id,
            operation_id,
        )


class InProcessCoordinator:
    """Deterministic Coordinator fake with ordered fault injection."""

    def __init__(
        self,
        *,
        task_id: str = "AR-0081",
        revision: int = 1,
        auth_reference: str = "AUTH-AR0081",
    ):
        _id("task_id", task_id)
        _id("auth_reference", auth_reference)
        if revision < 1:
            raise CoordinatorClientError("invalid_revision")
        self.task_id = task_id
        self.revision = revision
        self.auth_reference = auth_reference
        self.events: list[dict[str, Any]] = []
        self.operations: dict[str, dict[str, Any]] = {}
        self._faults: list[str] = []

    def inject(self, *faults: str) -> None:
        allowed = {
            "unavailable",
            "deadline_exceeded",
            "timeout",
            "ambiguous_after_commit",
            "malformed_response",
        }
        if any(fault not in allowed for fault in faults):
            raise CoordinatorClientError("unknown_fault")
        self._faults.extend(faults)

    def exchange(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._validate_request(request)
        operation_id = request["operation_id"]
        fingerprint = digest(
            {
                key: value
                for key, value in request.items()
                if key not in {"attempt", "timeout_ms"}
            }
        )
        previous = self.operations.get(operation_id)
        if previous is not None:
            if previous["fingerprint"] != fingerprint:
                raise CoordinatorRejected("changed_replay")
            return dict(previous["response"])
        if self._faults:
            fault = self._faults.pop(0)
            if fault == "ambiguous_after_commit":
                if request["operation"] == "write_event":
                    self._commit(request, fingerprint)
                raise CoordinatorRejected("ambiguous_outcome")
            if fault == "malformed_response":
                return {"disposition": "accepted", "correlation_id": "wrong"}
            raise CoordinatorRejected(fault)
        if request["expected_revision"] != self.revision:
            raise CoordinatorRejected("stale_revision")
        if request["operation"] == "read_revision":
            response = self._read(request)
        else:
            response = self._commit(request, fingerprint)
        self.operations[operation_id] = {
            "fingerprint": fingerprint,
            "response": dict(response),
        }
        return dict(response)

    def _validate_request(self, request: Mapping[str, Any]) -> None:
        if request.get("protocol") != PROTOCOL:
            raise CoordinatorRejected("unsupported_protocol")
        expected = {
            "task_id": self.task_id,
            "project_key": "agent-workflow-runtime",
            "auth_reference": self.auth_reference,
        }
        for key, value in expected.items():
            if request.get(key) != value:
                raise CoordinatorRejected("crossed_binding")
        for name in (
            "task_id",
            "session_id",
            "owner_id",
            "lease_id",
            "operation_id",
            "correlation_id",
            "auth_reference",
        ):
            try:
                _id(name, request.get(name))
            except CoordinatorClientError as exc:
                raise CoordinatorRejected(exc.args[0]) from exc
        if not isinstance(request.get("project_key"), str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,63}", request["project_key"]
        ):
            raise CoordinatorRejected("invalid_project_key")
        if not isinstance(request.get("worktree_key"), str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,127}", request["worktree_key"]
        ):
            raise CoordinatorRejected("invalid_worktree_key")
        if not isinstance(
            request.get("auth_proof_digest"), str
        ) or not DIGEST.fullmatch(request["auth_proof_digest"]):
            raise CoordinatorRejected("invalid_auth_proof")
        expected_auth = digest(
            {
                "auth_reference": self.auth_reference,
                "correlation_id": request["correlation_id"],
            }
        )
        if request["auth_proof_digest"] != expected_auth:
            raise CoordinatorRejected("invalid_auth_proof")
        if request.get("timeout_ms") not in range(1, MAX_TIMEOUT_MS + 1) or request.get(
            "attempt"
        ) not in range(1, MAX_ATTEMPTS + 1):
            raise CoordinatorRejected("invalid_bounds")
        if request.get("operation") not in {"read_revision", "write_event"} or _private(
            request
        ):
            raise CoordinatorRejected("privacy_or_operation_violation")

    def _read(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "disposition": "accepted",
            "task_id": self.task_id,
            "task_revision": self.revision,
            "event_count": len(self.events),
            "state_digest": digest(self.events),
            "correlation_id": request["correlation_id"],
            "operation_id": request["operation_id"],
        }

    def _commit(self, request: Mapping[str, Any], fingerprint: str) -> dict[str, Any]:
        if request.get("event_kind") is None or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,31}", request["event_kind"]
        ):
            raise CoordinatorRejected("invalid_event_kind")
        event_digest = request.get("event_digest")
        if not isinstance(event_digest, str) or not DIGEST.fullmatch(event_digest):
            raise CoordinatorRejected("invalid_event_digest")
        event = {
            "operation_id": request["operation_id"],
            "correlation_id": request["correlation_id"],
            "event_kind": request["event_kind"],
            "event_digest": event_digest,
            "task_revision": self.revision,
        }
        self.events.append(event)
        self.revision += 1
        response = {
            "disposition": "accepted",
            "task_id": self.task_id,
            "task_revision": self.revision,
            "event_count": len(self.events),
            "event_digest": event_digest,
            "correlation_id": request["correlation_id"],
            "operation_id": request["operation_id"],
        }
        self.operations[request["operation_id"]] = {
            "fingerprint": fingerprint,
            "response": dict(response),
        }
        return response

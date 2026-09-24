#!/usr/bin/env python3
"""Deterministic local AWQ/AWG/UI authority bridges for AR-0088.

The fakes in this module are authority-shaped test doubles.  They are not
network clients and they never derive an acceptance, guidance decision, or
human approval from runtime input.  A test harness (standing in for the
authority) must resolve pending requests explicitly; the runtime bridge can
only request, observe, retry, resume, and enforce the returned result.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

PROTOCOL = {"id": "awr-authority-bridges", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OPAQUE = re.compile(r"^(?:AR|JOB|OP|REQ|SES|LSE|WRK|EV|DEC|GATE|UI)-[A-Z0-9-]{1,63}$")
PRIVATE = re.compile(
    r"(?:credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|raw.?output|authorization|cookie|api.?key)",
    re.IGNORECASE,
)
AUTHORITIES = {"awq", "awg", "ui"}
OUTCOMES = {
    "awq": {"accepted", "rejected", "timeout", "unknown"},
    "awg": {"approved", "requires_ui", "rejected", "timeout", "unknown"},
    "ui": {"approved", "rejected", "timeout", "unknown"},
}
TRANSIENT = {"pending", "timeout", "unknown"}
USER_CHANGE_KINDS = {
    "refinement",
    "test_change",
    "specification_change",
    "repair_escalation",
}


class BridgeError(ValueError):
    """A fail-closed authority bridge violation."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fields(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise BridgeError("malformed " + name)
    return value


def _private(value: Any, location: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                found.append(location + "." + str(key))
            found.extend(_private(child, location + "." + str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_private(child, f"{location}[{index}]"))
    elif isinstance(value, str) and PRIVATE.search(value):
        found.append(location)
    return found


def binding_digest(binding: dict[str, Any]) -> str:
    return digest(binding)


def validate_binding(
    binding: dict[str, Any], *, expected_revision: int = 3
) -> dict[str, Any]:
    _fields(binding, {"task", "project", "worktree", "lease", "session"}, "binding")
    task = _fields(binding["task"], {"id", "revision"}, "task")
    project = _fields(binding["project"], {"key", "revision"}, "project")
    worktree = _fields(binding["worktree"], {"key", "digest"}, "worktree")
    lease = _fields(binding["lease"], {"id", "worker_id", "digest"}, "lease")
    session = _fields(binding["session"], {"id"}, "session")
    if task != {"id": "AR-0088", "revision": expected_revision}:
        raise BridgeError("stale task revision")
    if project["key"] != "agent-workflow-runtime" or not DIGEST.fullmatch(
        str(project["revision"])
    ):
        raise BridgeError("invalid project binding")
    if worktree["key"] != "agent-workflow-runtime-0088" or not DIGEST.fullmatch(
        str(worktree["digest"])
    ):
        raise BridgeError("invalid worktree binding")
    if not OPAQUE.fullmatch(str(lease["id"])) or not str(lease["id"]).startswith(
        "LSE-"
    ):
        raise BridgeError("invalid lease identity")
    if (
        not OPAQUE.fullmatch(str(lease["worker_id"]))
        or not str(lease["worker_id"]).startswith("WRK-")
        or not DIGEST.fullmatch(str(lease["digest"]))
    ):
        raise BridgeError("invalid lease binding")
    if not OPAQUE.fullmatch(str(session["id"])) or not str(session["id"]).startswith(
        "SES-"
    ):
        raise BridgeError("invalid session binding")
    if _private(binding):
        raise BridgeError("private binding material")
    return deepcopy(binding)


def _result(
    authority: str, status: str, *, attempt: int, operation_id: str, bind_digest: str
) -> dict[str, Any]:
    if status != "pending" and status not in OUTCOMES[authority]:
        raise BridgeError("invalid " + authority + " outcome")
    return {
        "authority": authority,
        "operation_id": operation_id,
        "attempt": attempt,
        "status": status,
        "binding_digest": bind_digest,
        "result_digest": digest(
            {
                "authority": authority,
                "operation_id": operation_id,
                "attempt": attempt,
                "status": status,
                "binding_digest": bind_digest,
            }
        ),
    }


class LocalAuthorityFake:
    """A deterministic authority fake with explicit pending resolution.

    ``respond`` is intentionally separate from :class:`AuthorityBridge`.
    Only the fake/harness can create an authoritative outcome; the bridge can
    never turn a request payload into approval.
    """

    def __init__(self, authority: str, responses: list[str] | None = None):
        if authority not in AUTHORITIES:
            raise BridgeError("unsupported authority")
        self.authority = authority
        self.responses = list(responses or [])
        self.pending: dict[str, tuple[str, int, str]] = {}
        self.completed: dict[str, dict[str, Any]] = {}
        self.last_observed: dict[str, dict[str, Any]] = {}

    def request(self, request: dict[str, Any]) -> dict[str, Any]:
        required = {
            "operation_id",
            "attempt",
            "max_attempts",
            "binding_digest",
            "request_digest",
        }
        _fields(request, required, "authority request")
        operation_id = request["operation_id"]
        if not OPAQUE.fullmatch(str(operation_id)) or not str(operation_id).startswith(
            "OP-"
        ):
            raise BridgeError("invalid operation id")
        if (
            request["attempt"] < 1
            or request["max_attempts"] < request["attempt"]
            or request["max_attempts"] > 5
        ):
            raise BridgeError("invalid retry bound")
        if not DIGEST.fullmatch(str(request["binding_digest"])) or not DIGEST.fullmatch(
            str(request["request_digest"])
        ):
            raise BridgeError("invalid request digest")
        fingerprint = digest(
            {
                key: request[key]
                for key in (
                    "operation_id",
                    "max_attempts",
                    "binding_digest",
                    "request_digest",
                )
            }
        )
        if operation_id in self.completed:
            prior = self.completed[operation_id]
            if prior["request_fingerprint"] != fingerprint:
                raise BridgeError("changed replay")
            return deepcopy(prior["result"])
        if operation_id in self.pending:
            prior_fingerprint, prior_attempt, prior_binding = self.pending[operation_id]
            if (prior_fingerprint, prior_binding) != (
                fingerprint,
                request["binding_digest"],
            ):
                raise BridgeError("changed pending replay")
            return _result(
                self.authority,
                "pending",
                attempt=prior_attempt,
                operation_id=operation_id,
                bind_digest=prior_binding,
            )
        status = self.responses.pop(0) if self.responses else "unknown"
        if status == "pending":
            self.pending[operation_id] = (
                fingerprint,
                request["attempt"],
                request["binding_digest"],
            )
            return _result(
                self.authority,
                "pending",
                attempt=request["attempt"],
                operation_id=operation_id,
                bind_digest=request["binding_digest"],
            )
        if status not in OUTCOMES[self.authority]:
            raise BridgeError("ambiguous authority outcome")
        return self._complete(
            operation_id,
            fingerprint,
            request["attempt"],
            request["binding_digest"],
            status,
        )

    def respond(self, operation_id: str, status: str) -> dict[str, Any]:
        """Resolve a pending operation as the authority/test harness."""
        if operation_id not in self.pending:
            raise BridgeError("operation is not pending")
        if status not in OUTCOMES[self.authority] - {"pending"}:
            raise BridgeError("invalid authoritative response")
        fingerprint, attempt, bind_digest = self.pending.pop(operation_id)
        return self._complete(operation_id, fingerprint, attempt, bind_digest, status)

    def _complete(
        self,
        operation_id: str,
        fingerprint: str,
        attempt: int,
        bind_digest: str,
        status: str,
    ) -> dict[str, Any]:
        result = _result(
            self.authority,
            status,
            attempt=attempt,
            operation_id=operation_id,
            bind_digest=bind_digest,
        )
        if status not in {"timeout", "unknown"}:
            self.completed[operation_id] = {
                "request_fingerprint": fingerprint,
                "result": deepcopy(result),
            }
        else:
            # Keep the observation available for resume.  It is deliberately
            # not a completed result, so a caller must explicitly retry it.
            self.last_observed[operation_id] = deepcopy(result)
        return result

    def observe(self, operation_id: str) -> dict[str, Any]:
        if operation_id in self.completed:
            return deepcopy(self.completed[operation_id]["result"])
        if operation_id in self.last_observed:
            return deepcopy(self.last_observed[operation_id])
        if operation_id in self.pending:
            _fingerprint, attempt, bind_digest = self.pending[operation_id]
            return _result(
                self.authority,
                "pending",
                attempt=attempt,
                operation_id=operation_id,
                bind_digest=bind_digest,
            )
        raise BridgeError("unknown operation")


@dataclass
class Operation:
    authority: str
    operation_id: str
    request_id: str
    kind: str
    change_kind: str
    max_attempts: int
    binding: dict[str, Any]
    request_digest: str
    attempts: list[dict[str, Any]] = field(default_factory=list)
    status: str = "new"
    resumed: int = 0


class AuthorityBridge:
    """Runtime-side request/observe/retry/resume facade.

    The facade never exposes a method that accepts a runtime-supplied final
    authority outcome.  ``respond`` belongs to ``LocalAuthorityFake``.
    """

    def __init__(
        self,
        binding: dict[str, Any],
        fakes: dict[str, LocalAuthorityFake],
        *,
        expected_revision: int = 3,
    ):
        self.binding = validate_binding(binding, expected_revision=expected_revision)
        if set(fakes) != AUTHORITIES or any(
            fake.authority != authority for authority, fake in fakes.items()
        ):
            raise BridgeError("authority fake partition incomplete")
        self.fakes = fakes
        self.operations: dict[str, Operation] = {}

    def request(
        self,
        authority: str,
        request_id: str,
        kind: str,
        payload: Any,
        *,
        operation_id: str,
        max_attempts: int = 3,
        change_kind: str = "none",
    ) -> dict[str, Any]:
        if (
            authority not in AUTHORITIES
            or not OPAQUE.fullmatch(str(request_id))
            or not str(request_id).startswith("REQ-")
        ):
            raise BridgeError("invalid authority request")
        if not OPAQUE.fullmatch(str(operation_id)) or not str(operation_id).startswith(
            "OP-"
        ):
            raise BridgeError("invalid operation id")
        if max_attempts < 1 or max_attempts > 5:
            raise BridgeError("invalid retry bound")
        if change_kind not in USER_CHANGE_KINDS | {"none", "ordinary_alternative"}:
            raise BridgeError("invalid change kind")
        if authority == "awq" and kind != "evidence":
            raise BridgeError("AWQ only accepts evidence requests")
        if authority == "awg" and kind != "discussion":
            raise BridgeError("AWG only accepts discussion requests")
        if authority == "ui" and kind != "human_gate":
            raise BridgeError("UI only accepts human-gate requests")
        if operation_id in self.operations:
            operation = self.operations[operation_id]
            if (
                operation.request_digest != digest(payload)
                or operation.binding != self.binding
            ):
                raise BridgeError("changed or crossed operation replay")
            return self._view(operation)
        operation = Operation(
            authority,
            operation_id,
            request_id,
            kind,
            change_kind,
            max_attempts,
            deepcopy(self.binding),
            digest(payload),
        )
        self.operations[operation_id] = operation
        self._send(operation)
        return self._view(operation)

    def _send(self, operation: Operation) -> None:
        attempt = len(operation.attempts) + 1
        request = {
            "operation_id": operation.operation_id,
            "attempt": attempt,
            "max_attempts": operation.max_attempts,
            "binding_digest": binding_digest(operation.binding),
            "request_digest": operation.request_digest,
        }
        observed = self.fakes[operation.authority].request(request)
        if observed["binding_digest"] != binding_digest(operation.binding):
            raise BridgeError("crossed authority result")
        operation.attempts.append(deepcopy(observed))
        operation.status = observed["status"]
        if operation.status == "timeout" and attempt < operation.max_attempts:
            # A timeout is observed, not silently retried.  The caller must
            # invoke retry(), making the control flow auditable.
            operation.status = "timeout"

    def observe(self, operation_id: str) -> dict[str, Any]:
        operation = self._operation(operation_id)
        observed = self.fakes[operation.authority].observe(operation_id)
        if observed["binding_digest"] != binding_digest(operation.binding):
            raise BridgeError("crossed authority result")
        if not operation.attempts or observed != operation.attempts[-1]:
            operation.attempts.append(deepcopy(observed))
        operation.status = observed["status"]
        return self._view(operation)

    def retry(self, operation_id: str) -> dict[str, Any]:
        operation = self._operation(operation_id)
        if operation.status not in {"timeout", "unknown"}:
            raise BridgeError("only timeout or unknown outcomes may be retried")
        if len(operation.attempts) >= operation.max_attempts:
            operation.status = "blocked"
            return self._view(operation)
        self._send(operation)
        return self._view(operation)

    def resume(self, operation_id: str) -> dict[str, Any]:
        operation = self._operation(operation_id)
        operation.resumed += 1
        return self.observe(operation_id)

    def _operation(self, operation_id: str) -> Operation:
        operation = self.operations.get(operation_id)
        if operation is None:
            raise BridgeError("unknown operation")
        return operation

    def _view(self, operation: Operation) -> dict[str, Any]:
        return {
            "authority": operation.authority,
            "operation_id": operation.operation_id,
            "request_id": operation.request_id,
            "kind": operation.kind,
            "change_kind": operation.change_kind,
            "max_attempts": operation.max_attempts,
            "attempts": deepcopy(operation.attempts),
            "status": operation.status,
            "binding_digest": binding_digest(operation.binding),
            "resumed": operation.resumed,
        }

    def finalize_change(
        self, awg_operation_id: str, ui_operation_id: str
    ) -> dict[str, Any]:
        awg = self._operation(awg_operation_id)
        ui = self._operation(ui_operation_id)
        if awg.binding != self.binding or ui.binding != self.binding:
            raise BridgeError("change binding mismatch")
        if (
            awg.authority != "awg"
            or ui.authority != "ui"
            or awg.change_kind not in USER_CHANGE_KINDS
        ):
            raise BridgeError("invalid mandatory change gate")
        if awg.status != "requires_ui":
            raise BridgeError("AWG has not routed the required change to UI")
        if ui.status != "approved":
            raise BridgeError("UI has not approved the required change")
        return {
            "status": "authorized",
            "awg_operation_id": awg_operation_id,
            "ui_operation_id": ui_operation_id,
            "binding_digest": binding_digest(self.binding),
        }


def validate_record(
    record: dict[str, Any], *, expected_revision: int = 3
) -> dict[str, Any]:
    top = {
        "schema_version",
        "protocol",
        "binding",
        "operations",
        "change_control",
        "offline",
    }
    _fields(record, top, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise BridgeError("unsupported protocol")
    binding = validate_binding(record["binding"], expected_revision=expected_revision)
    if record["offline"] != {
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
        "durable_state": "not_performed",
    }:
        raise BridgeError("unsafe offline boundary")
    operations = record["operations"]
    if not isinstance(operations, list) or not 2 <= len(operations) <= 32:
        raise BridgeError("invalid operation count")
    ids = set()
    for item in operations:
        fields = {
            "authority",
            "operation_id",
            "request_id",
            "kind",
            "change_kind",
            "max_attempts",
            "request_digest",
            "attempts",
            "status",
            "resumed",
            "binding_digest",
        }
        _fields(item, fields, "operation")
        if (
            item["operation_id"] in ids
            or not OPAQUE.fullmatch(str(item["operation_id"]))
            or not str(item["operation_id"]).startswith("OP-")
        ):
            raise BridgeError("duplicate or invalid operation")
        ids.add(item["operation_id"])
        authority = item["authority"]
        if (
            authority not in AUTHORITIES
            or item["kind"]
            != {"awq": "evidence", "awg": "discussion", "ui": "human_gate"}[authority]
        ):
            raise BridgeError("authority kind mismatch")
        if (
            not OPAQUE.fullmatch(str(item["request_id"]))
            or not str(item["request_id"]).startswith("REQ-")
            or item["change_kind"]
            not in USER_CHANGE_KINDS | {"none", "ordinary_alternative"}
        ):
            raise BridgeError("invalid operation request")
        if (
            not isinstance(item["max_attempts"], int)
            or not 1 <= item["max_attempts"] <= 5
            or not DIGEST.fullmatch(str(item["request_digest"]))
        ):
            raise BridgeError("invalid operation retry contract")
        if (
            item["binding_digest"] != binding_digest(binding)
            or not isinstance(item["resumed"], int)
            or item["resumed"] < 0
        ):
            raise BridgeError("operation binding or resume mismatch")
        attempts = item["attempts"]
        if (
            not isinstance(attempts, list)
            or not attempts
            or len(attempts) > item["max_attempts"]
        ):
            raise BridgeError("invalid attempt trace")
        for number, attempt in enumerate(attempts, 1):
            _fields(
                attempt,
                {
                    "authority",
                    "operation_id",
                    "attempt",
                    "status",
                    "binding_digest",
                    "result_digest",
                },
                "attempt",
            )
            if (
                attempt["authority"] != authority
                or attempt["operation_id"] != item["operation_id"]
                or attempt["attempt"] != number
                or attempt["binding_digest"] != item["binding_digest"]
                or attempt["status"] not in OUTCOMES[authority] | {"pending"}
                or not DIGEST.fullmatch(str(attempt["result_digest"]))
            ):
                raise BridgeError("invalid attempt result")
        if (
            item["status"] not in OUTCOMES[authority] | {"pending", "blocked"}
            or item["status"] != attempts[-1]["status"]
            and not (
                item["status"] == "blocked"
                and attempts[-1]["status"] in {"unknown", "timeout"}
                and len(attempts) == item["max_attempts"]
            )
        ):
            raise BridgeError("invalid final operation status")
        if item["status"] == "blocked" and attempts[-1]["status"] not in {
            "unknown",
            "timeout",
        }:
            raise BridgeError("blocked operation was not fail-closed")
        if (
            item["status"] in {"accepted", "approved"}
            and attempts[-1]["status"] != item["status"]
        ):
            raise BridgeError("authority approval manufactured")
    change = _fields(
        record["change_control"],
        {
            "required",
            "change_kind",
            "awg_operation_id",
            "ui_operation_id",
            "status",
            "binding_digest",
        },
        "change control",
    )
    if (
        change["required"] is not True
        or change["change_kind"] not in USER_CHANGE_KINDS
        or change["binding_digest"] != binding_digest(binding)
    ):
        raise BridgeError("invalid mandatory change control")
    by_id = {item["operation_id"]: item for item in operations}
    awg = by_id.get(change["awg_operation_id"])
    ui = by_id.get(change["ui_operation_id"])
    if (
        not awg
        or not ui
        or awg["authority"] != "awg"
        or ui["authority"] != "ui"
        or awg["change_kind"] != change["change_kind"]
        or ui["change_kind"] != change["change_kind"]
    ):
        raise BridgeError("mandatory AWG/UI operations missing")
    expected_change_status = (
        "authorized"
        if awg["status"] == "requires_ui" and ui["status"] == "approved"
        else "blocked"
    )
    if change["status"] != expected_change_status:
        raise BridgeError("change-control outcome manufactured or fail-open")
    if _private(record):
        raise BridgeError("private authority material")
    return {
        "protocol": "awr-authority-bridges@1.0.0",
        "operations": len(operations),
        "pending": sum(
            any(attempt["status"] == "pending" for attempt in item["attempts"])
            for item in operations
        ),
        "change_status": change["status"],
        "binding_digest": binding_digest(binding),
    }

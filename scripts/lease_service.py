#!/usr/bin/env python3
"""Deterministic shared lease boundary for AR-0082.

The service is deliberately transport-neutral.  ``LocalCoordinatorFake`` is
the only implementation supplied here; it models the Coordinator CAS and
durable operation-result boundary without sockets, files, providers, or LLMs.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol


class LeaseError(ValueError):
    """A rejected or unresolved lease operation."""


class UnknownLeaseOutcome(LeaseError):
    """The Coordinator committed, but the response was not observed."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


_IDS = {
    "task_id": re.compile(r"^AR-[0-9]{4}$"),
    "project_key": re.compile(r"^[a-z][a-z0-9-]{0,63}$"),
    "worktree_key": re.compile(r"^[a-z][a-z0-9-]{0,127}$"),
    "owner_id": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"),
    "lease_id": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
    "operation_id": re.compile(r"^OP-[A-Z0-9-]{1,63}$"),
}


def _id(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _IDS[name].fullmatch(value):
        raise LeaseError(f"invalid_{name}")
    return value


@dataclass(frozen=True)
class LeaseBinding:
    task_id: str
    project_key: str
    worktree_key: str

    def validate(self) -> None:
        _id("task_id", self.task_id)
        _id("project_key", self.project_key)
        _id("worktree_key", self.worktree_key)

    def as_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "task_id": self.task_id,
            "project_key": self.project_key,
            "worktree_key": self.worktree_key,
        }


class LeaseTransport(Protocol):
    def apply(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class LeaseService:
    """Typed, bounded client for the shared Coordinator lease boundary."""

    def __init__(self, transport: LeaseTransport, binding: LeaseBinding):
        binding.validate()
        self.transport = transport
        self.binding = binding

    def acquire(self, operation_id: str, *, expected_revision: int, owner_id: str,
                lease_id: str, now: int, expires: int) -> Mapping[str, Any]:
        return self._call("acquire", operation_id, expected_revision, now,
                          owner_id=owner_id, lease_id=lease_id,
                          new_expires=expires)

    def heartbeat(self, operation_id: str, *, expected_revision: int, owner_id: str,
                  lease_id: str, fence: int, now: int,
                  expires: int) -> Mapping[str, Any]:
        return self._call("heartbeat", operation_id, expected_revision, now,
                          owner_id=owner_id, lease_id=lease_id, fence=fence,
                          new_expires=expires)

    def handoff(self, operation_id: str, *, expected_revision: int, owner_id: str,
                lease_id: str, fence: int, new_owner_id: str, new_lease_id: str,
                now: int, expires: int) -> Mapping[str, Any]:
        return self._call("handoff", operation_id, expected_revision, now,
                          owner_id=owner_id, lease_id=lease_id, fence=fence,
                          new_owner_id=new_owner_id, new_lease_id=new_lease_id,
                          new_expires=expires)

    def recover_expired(self, operation_id: str, *, expected_revision: int,
                        owner_id: str, lease_id: str, fence: int,
                        new_owner_id: str, new_lease_id: str, now: int,
                        expires: int) -> Mapping[str, Any]:
        return self._call("recover_expired", operation_id, expected_revision, now,
                          owner_id=owner_id, lease_id=lease_id, fence=fence,
                          new_owner_id=new_owner_id, new_lease_id=new_lease_id,
                          new_expires=expires)

    def release(self, operation_id: str, *, expected_revision: int, owner_id: str,
                lease_id: str, fence: int, now: int) -> Mapping[str, Any]:
        return self._call("release", operation_id, expected_revision, now,
                          owner_id=owner_id, lease_id=lease_id, fence=fence)

    def _call(self, operation: str, operation_id: str, expected_revision: int,
              now: int, **values: Any) -> Mapping[str, Any]:
        _id("operation_id", operation_id)
        if operation not in {"acquire", "heartbeat", "handoff", "recover_expired", "release"}:
            raise LeaseError("unknown_operation")
        if not isinstance(expected_revision, int) or expected_revision < 1:
            raise LeaseError("invalid_expected_revision")
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise LeaseError("invalid_time")
        request = {**self.binding.as_dict(), "operation": operation,
                   "operation_id": operation_id, "expected_revision": expected_revision,
                   "now": now, **values}
        return self.transport.apply(request)


class LocalCoordinatorFake:
    """CAS Coordinator fake with deterministic crash and delayed-response faults."""

    def __init__(self, binding: LeaseBinding, *, revision: int = 1):
        binding.validate()
        if revision < 1:
            raise LeaseError("invalid_revision")
        self.binding = binding
        self.revision = revision
        self.owner_id: str | None = None
        self.lease_id: str | None = None
        self.fence = 0
        self.expires = 0
        self.clock = 0
        self.operations: dict[str, dict[str, Any]] = {}
        self.journal: list[dict[str, Any]] = []
        self.faults: list[str] = []
        self.delayed: list[dict[str, Any]] = []

    def inject(self, *faults: str) -> None:
        allowed = {"ambiguous_after_commit", "delay_response"}
        if any(fault not in allowed for fault in faults):
            raise LeaseError("unknown_fault")
        self.faults.extend(faults)

    def apply(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        request = dict(request)
        self._validate(request)
        operation_id = request["operation_id"]
        fingerprint = digest(request)
        prior = self.operations.get(operation_id)
        if prior is not None:
            if prior["fingerprint"] != fingerprint:
                raise LeaseError("changed_replay")
            return deepcopy(prior["response"])
        if request["expected_revision"] != self.revision:
            raise LeaseError("stale_cas_revision")
        self._apply_mutation(request)
        response = self._response(operation_id)
        self.operations[operation_id] = {"fingerprint": fingerprint,
                                         "response": deepcopy(response)}
        self._journal(request, response)
        fault = self.faults.pop(0) if self.faults else None
        if fault == "ambiguous_after_commit":
            raise UnknownLeaseOutcome("ambiguous_outcome")
        if fault == "delay_response":
            self.delayed.append(deepcopy(response))
            raise UnknownLeaseOutcome("delayed_response")
        return response

    def deliver_delayed(self) -> Mapping[str, Any]:
        if not self.delayed:
            raise LeaseError("no_delayed_response")
        return self.delayed.pop(0)

    def snapshot(self) -> dict[str, Any]:
        return {"revision": self.revision, "owner_id": self.owner_id,
                "lease_id": self.lease_id, "fence": self.fence,
                "expires": self.expires, "clock": self.clock}

    def _validate(self, request: Mapping[str, Any]) -> None:
        required = {"task_id", "project_key", "worktree_key", "operation",
                    "operation_id", "expected_revision", "now"}
        if not required.issubset(request) or set(request) - required - {
            "owner_id", "lease_id", "fence", "new_owner_id", "new_lease_id",
            "new_expires",
        }:
            raise LeaseError("invalid_request_shape")
        for key, value in self.binding.as_dict().items():
            if request.get(key) != value:
                raise LeaseError("crossed_binding")
        _id("operation_id", request["operation_id"])
        if request["operation"] not in {"acquire", "heartbeat", "handoff", "recover_expired", "release"}:
            raise LeaseError("unknown_operation")
        if not isinstance(request["expected_revision"], int) or request["expected_revision"] < 1:
            raise LeaseError("invalid_expected_revision")
        if not isinstance(request["now"], int) or isinstance(request["now"], bool):
            raise LeaseError("invalid_time")
        for key in ("owner_id", "new_owner_id"):
            if key in request:
                _id("owner_id", request[key])
        for key in ("lease_id", "new_lease_id"):
            if key in request:
                _id("lease_id", request[key])
        if "fence" in request and (not isinstance(request["fence"], int) or request["fence"] < 1):
            raise LeaseError("invalid_fence")
        if "new_expires" in request and (not isinstance(request["new_expires"], int) or request["new_expires"] < 1):
            raise LeaseError("invalid_expiry")

    def _apply_mutation(self, request: Mapping[str, Any]) -> None:
        operation, now = request["operation"], request["now"]
        if now < self.clock:
            raise LeaseError("non_monotonic_clock")
        if operation == "acquire":
            if self.owner_id is not None:
                raise LeaseError("already_owned")
            if request.get("new_expires", 0) <= now:
                raise LeaseError("invalid_expiry")
            self.owner_id, self.lease_id = request["owner_id"], request["lease_id"]
            self.fence += 1
            self.expires = request["new_expires"]
        else:
            if (request.get("owner_id"), request.get("lease_id"), request.get("fence")) != (
                self.owner_id, self.lease_id, self.fence
            ):
                raise LeaseError("owner_or_fence_mismatch")
            if operation == "heartbeat":
                if now >= self.expires or now <= self.clock or request.get("new_expires", 0) <= self.expires:
                    raise LeaseError("invalid_heartbeat")
                self.expires = request["new_expires"]
            elif operation == "handoff":
                if now >= self.expires:
                    raise LeaseError("lease_expired")
                self._replace(request, now)
            elif operation == "recover_expired":
                if now < self.expires:
                    raise LeaseError("lease_not_expired")
                self._replace(request, now)
            elif operation == "release":
                if now >= self.expires:
                    raise LeaseError("lease_expired")
                self.owner_id = self.lease_id = None
                self.expires = 0
            else:
                raise LeaseError("unknown_operation")
        self.clock = now
        self.revision += 1

    def _replace(self, request: Mapping[str, Any], now: int) -> None:
        if not request.get("new_owner_id") or not request.get("new_lease_id"):
            raise LeaseError("invalid_replacement")
        if request.get("new_expires", 0) <= now:
            raise LeaseError("invalid_expiry")
        self.owner_id, self.lease_id = request["new_owner_id"], request["new_lease_id"]
        self.expires = request["new_expires"]
        self.fence += 1

    def _response(self, operation_id: str) -> dict[str, Any]:
        return {"disposition": "accepted", "operation_id": operation_id,
                "task_id": self.binding.task_id, "project_key": self.binding.project_key,
                "worktree_key": self.binding.worktree_key, "task_revision": self.revision,
                "owner_id": self.owner_id, "lease_id": self.lease_id,
                "fence": self.fence, "expires": self.expires}

    def _journal(self, request: Mapping[str, Any], response: Mapping[str, Any]) -> None:
        entry = {"operation_id": request["operation_id"], "operation": request["operation"],
                 "task_revision": response["task_revision"], "fence": response["fence"]}
        entry["previous_digest"] = self.journal[-1]["digest"] if self.journal else "sha256:" + "0" * 64
        entry["digest"] = digest(entry)
        self.journal.append(entry)


def run_interleaving(fake: LocalCoordinatorFake, workers: list[str], *, rounds: int = 4) -> list[dict[str, Any]]:
    """Run a fixed round-robin schedule and return accepted/error evidence."""
    binding = fake.binding
    clients = {owner: LeaseService(fake, binding) for owner in workers}
    evidence: list[dict[str, Any]] = []
    for round_no in range(rounds):
        for index, owner in enumerate(workers):
            try:
                if fake.owner_id is None:
                    response = clients[owner].acquire(
                        f"OP-AR0082-{round_no}-{index}", expected_revision=fake.revision,
                        owner_id=owner, lease_id=f"LSE-{owner[4:]}", now=fake.clock,
                        expires=fake.clock + 3)
                elif fake.owner_id == owner and fake.clock < fake.expires:
                    response = clients[owner].heartbeat(
                        f"OP-AR0082-{round_no}-{index}", expected_revision=fake.revision,
                        owner_id=owner, lease_id=fake.lease_id or "LSE-INVALID",
                        fence=fake.fence, now=fake.clock + 1, expires=fake.expires + 2)
                else:
                    raise LeaseError("not_current_owner")
                evidence.append({"worker": owner, "round": round_no, "result": "accepted",
                                 "fence": response["fence"]})
            except (LeaseError, UnknownLeaseOutcome) as exc:
                evidence.append({"worker": owner, "round": round_no, "result": str(exc)})
    if fake.owner_id is not None and fake.clock < fake.expires:
        LeaseService(fake, binding).release(
            "OP-AR0082-FINAL", expected_revision=fake.revision,
            owner_id=fake.owner_id, lease_id=fake.lease_id or "LSE-INVALID",
            fence=fake.fence, now=fake.clock
        )
    return evidence

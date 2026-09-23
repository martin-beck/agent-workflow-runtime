#!/usr/bin/env python3
"""Offline reference implementation for the AR-0018 Supervisor boundary.

This module is deliberately an in-memory model.  It validates the admission
binding and applies fenced lifecycle actions; it does not launch, stop, or
recover a real process and it does not write Coordinator state.
"""

from dataclasses import dataclass, field
import hashlib
import json
import re


class SupervisorRuntimeError(ValueError):
    """A fail-closed admission, lease, lifecycle, or evidence violation."""


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTITIES = {
    "session": re.compile(r"^SES-[A-Z0-9-]{1,63}$"),
    "worker": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"),
    "lease": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
}


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class SupervisorAdmission:
    task_id: str
    task_revision: int
    project_key: str
    project_revision: str
    worktree_key: str
    worktree_revision: str
    worktree_digest: str
    session_id: str
    worker_id: str
    lease_id: str
    lease_expires: int

    def validate(self):
        if not re.fullmatch(r"AR-[0-9]{4}", self.task_id):
            raise SupervisorRuntimeError("malformed task id")
        if not isinstance(self.task_revision, int) or isinstance(self.task_revision, bool) or self.task_revision < 1:
            raise SupervisorRuntimeError("task revision must be positive")
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", self.project_key):
            raise SupervisorRuntimeError("malformed project key")
        if not re.fullmatch(r"[0-9a-f]{40}", self.project_revision) or not re.fullmatch(r"[0-9a-f]{40}", self.worktree_revision):
            raise SupervisorRuntimeError("malformed project revision")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", self.worktree_key) or not DIGEST.fullmatch(self.worktree_digest):
            raise SupervisorRuntimeError("malformed worktree binding")
        for kind, value in (("session", self.session_id), ("worker", self.worker_id), ("lease", self.lease_id)):
            if not IDENTITIES[kind].fullmatch(value):
                raise SupervisorRuntimeError("malformed " + kind + " id")
        if not isinstance(self.lease_expires, int) or isinstance(self.lease_expires, bool) or self.lease_expires < 1:
            raise SupervisorRuntimeError("malformed lease expiry")
        return self


@dataclass
class SupervisorRuntime:
    admission: SupervisorAdmission
    state: str = "admitted"
    now: int = 0
    sequence: int = 0
    seen_actions: set = field(default_factory=set)
    actions: list = field(default_factory=list)

    def __post_init__(self):
        self.admission.validate()

    def apply(self, action_id, operation, *, worker, lease, now, new_worker=None, new_lease=None, new_expiry=None):
        if not re.fullmatch(r"ACT-[A-Z0-9-]{1,63}", action_id) or action_id in self.seen_actions:
            raise SupervisorRuntimeError("replayed or malformed action")
        if worker != self.admission.worker_id or lease != self.admission.lease_id:
            raise SupervisorRuntimeError("worker or lease fence mismatch")
        if not isinstance(now, int) or isinstance(now, bool) or now < self.now:
            raise SupervisorRuntimeError("non-monotonic observation time")
        if operation != "stale_recover" and now >= self.admission.lease_expires:
            raise SupervisorRuntimeError("lease expired")
        if operation == "heartbeat":
            if self.state != "active" or now <= self.now or not isinstance(new_expiry, int) or new_expiry <= self.admission.lease_expires:
                raise SupervisorRuntimeError("invalid heartbeat")
            self.admission = SupervisorAdmission(**{**self.admission.__dict__, "lease_expires": new_expiry})
        elif operation in {"handoff", "stale_recover"}:
            if operation == "stale_recover" and now < self.admission.lease_expires:
                raise SupervisorRuntimeError("recovery requires expiry")
            if not re.fullmatch(r"WRK-[A-Z0-9-]{1,63}", str(new_worker or "")) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,63}", str(new_lease or "")):
                raise SupervisorRuntimeError("replacement binding required")
            if not isinstance(new_expiry, int) or new_expiry <= now:
                raise SupervisorRuntimeError("replacement expiry must be future")
            if operation == "handoff" and self.state != "active":
                raise SupervisorRuntimeError("handoff requires active state")
            if operation == "stale_recover" and self.state not in {"active", "handed_off"}:
                raise SupervisorRuntimeError("recovery requires resumable state")
            self.admission = SupervisorAdmission(**{**self.admission.__dict__, "worker_id": new_worker, "lease_id": new_lease, "lease_expires": new_expiry})
            self.state = "handed_off" if operation == "handoff" else "recovered"
        else:
            transitions = {
                ("admitted", "start"): "active", ("active", "cancel"): "cancelling",
                ("cancelling", "cancel_ack"): "closed", ("handed_off", "resume"): "active",
                ("recovered", "resume"): "active", ("active", "complete"): "closed",
                ("active", "fail"): "failed",
            }
            target = transitions.get((self.state, operation))
            if target is None:
                raise SupervisorRuntimeError("invalid lifecycle transition")
            self.state = target
        self.now = now
        self.sequence += 1
        self.seen_actions.add(action_id)
        self.actions.append({"id": action_id, "sequence": self.sequence, "operation": operation, "state": self.state, "worker": self.admission.worker_id, "lease": self.admission.lease_id, "time": now, "lease_expires": self.admission.lease_expires})
        return self.state

    def evidence(self, specification_digest):
        if not DIGEST.fullmatch(specification_digest):
            raise SupervisorRuntimeError("malformed specification digest")
        return {"task_revision": self.admission.task_revision, "specification_digest": specification_digest, "lifecycle_digest": digest(self.actions), "action_count": len(self.actions), "final_state": self.state}

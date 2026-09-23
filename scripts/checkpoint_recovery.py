#!/usr/bin/env python3
"""Offline standard-library model for AR-0007 checkpoint recovery."""

from dataclasses import dataclass, field


class RecoveryError(ValueError):
    """A fail-closed checkpoint or recovery violation."""


@dataclass
class RecoveryState:
    task_revision: int
    session_id: str
    worktree_key: str
    worker_id: str
    lease_id: str
    state: str = "active"
    sequence: int = 0
    checkpoint: dict | None = None
    operations: dict = field(default_factory=dict)
    event_ids: set = field(default_factory=set)

    def action(self, operation, *, event_id, worker, lease, payload=None):
        if event_id in self.event_ids:
            raise RecoveryError("replayed event")
        if worker != self.worker_id or lease != self.lease_id:
            raise RecoveryError("worker or lease fence mismatch")
        payload = payload or {}
        if operation == "checkpoint":
            self._checkpoint(event_id, payload)
        elif operation == "retry":
            self._retry(event_id, payload)
        elif operation in {"host_failed", "agent_failed"}:
            self._transition(operation, "interrupted")
        elif operation == "interrupt":
            self._transition(operation, "interrupting")
        elif operation == "interrupt_ack":
            self._transition(operation, "interrupted")
        elif operation == "recover":
            if self.state != "interrupted" or not self.checkpoint:
                raise RecoveryError("recovery requires an interruption and checkpoint")
            new_worker, new_lease = payload.get("new_worker"), payload.get("new_lease")
            if not new_worker or not new_lease or new_worker == self.worker_id or new_lease == self.lease_id:
                raise RecoveryError("recovery requires a new worker and lease")
            self.worker_id, self.lease_id = new_worker, new_lease
            self.state = "recovering"
        elif operation == "replay":
            if self.state != "recovering" or not self.checkpoint or payload.get("checkpoint_id") != self.checkpoint["checkpoint_id"]:
                raise RecoveryError("replay requires the verified checkpoint")
            self._transition(operation, "replayed")
        elif operation == "resume":
            if self.state not in {"recovering", "replayed"}:
                raise RecoveryError("resume requires recovery")
            self.state = "active"
        elif operation == "complete":
            self._transition(operation, "completed")
        elif operation == "fail":
            self._transition(operation, "failed")
        else:
            raise RecoveryError("unknown operation")
        self.event_ids.add(event_id)
        self.sequence += 1
        return self.state

    def _transition(self, operation, target):
        allowed = {("active", "interrupt"): "interrupting", ("active", "host_failed"): "interrupted",
                   ("active", "agent_failed"): "interrupted", ("interrupting", "interrupt_ack"): "interrupted",
                   ("recovering", "replay"): "replayed",
                   ("replayed", "resume"): "active", ("recovering", "resume"): "active",
                   ("active", "complete"): "completed", ("active", "fail"): "failed"}
        if (self.state, operation) not in allowed or allowed[(self.state, operation)] != target:
            raise RecoveryError("invalid lifecycle transition")
        self.state = target

    def _checkpoint(self, event_id, payload):
        required = {"checkpoint_id", "operation_id", "sequence", "state_digest", "input_digest", "result_digest", "durable_digest"}
        if self.state != "active" or set(payload) != required or payload["sequence"] != self.sequence + 1:
            raise RecoveryError("malformed or non-active checkpoint")
        op = payload["operation_id"]
        if op in self.operations:
            raise RecoveryError("duplicate operation")
        self.operations[op] = dict(payload)
        self.checkpoint = dict(payload)

    def _retry(self, event_id, payload):
        required = {"operation_id", "sequence", "state_digest", "input_digest", "result_digest", "durable_digest"}
        if set(payload) != required or payload["operation_id"] not in self.operations:
            raise RecoveryError("unknown retry")
        original = self.operations[payload["operation_id"]]
        if any(payload[key] != original[key] for key in required - {"sequence"}):
            raise RecoveryError("changed idempotent operation")
        if payload["sequence"] <= original["sequence"]:
            raise RecoveryError("retry sequence must advance")

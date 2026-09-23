#!/usr/bin/env python3
"""Offline reference model for the AR-0014 runtime contract."""

from dataclasses import dataclass, field


class RuntimeModelError(ValueError):
    """A fail-closed runtime trace violation."""


TRANSITIONS = {
    ("new", "admit"): "admitted",
    ("admitted", "claim"): "claimed",
    ("claimed", "start"): "started",
    ("started", "execute"): "executing",
    ("executing", "oracle_required"): "oracle_pending",
    ("oracle_pending", "oracle_answer"): "executing",
    ("executing", "checkpoint"): "executing",
    ("executing", "interrupt"): "interrupted",
    ("interrupted", "recover"): "recovering",
    ("recovering", "resume"): "executing",
    ("executing", "publish"): "publishing",
    ("publishing", "reconcile"): "reconciled",
    ("reconciled", "complete"): "completed",
    ("executing", "fail"): "failed",
    ("oracle_pending", "fail"): "failed",
    ("recovering", "fail"): "failed",
    ("publishing", "fail"): "failed",
}

AUTHORITIES = {
    "admit": "coordinator", "claim": "coordinator", "start": "runtime",
    "execute": "runtime", "oracle_required": "awg", "oracle_answer": "awg",
    "checkpoint": "runtime", "interrupt": "runtime", "recover": "coordinator",
    "resume": "runtime", "publish": "runtime", "reconcile": "coordinator",
    "complete": "coordinator", "fail": "runtime",
}

PAYLOAD_FIELDS = {
    "admit": {"revision", "worktree_digest"},
    "claim": {"claim_digest"},
    "start": {"session_id"},
    "execute": {"operation_digest"},
    "oracle_required": {"admission_digest", "admission_status"},
    "oracle_answer": {"decision", "decision_digest"},
    "checkpoint": {"checkpoint_digest", "operation_digest"},
    "interrupt": {"reason_digest"},
    "recover": {"new_worker", "new_lease", "checkpoint_digest"},
    "resume": {"checkpoint_digest"},
    "publish": {"head_digest", "merge_status", "publication_status"},
    "reconcile": {"reconciled", "observation_digest"},
    "complete": {"completion_observed"},
    "fail": {"failure_digest"},
}


@dataclass
class RuntimeState:
    revision: int
    session_id: str
    worktree_digest: str
    worker_id: str
    lease_id: str
    state: str = "new"
    event_ids: set = field(default_factory=set)
    checkpoint_digest: str | None = None

    def apply(self, action):
        if action["event_id"] in self.event_ids:
            raise RuntimeModelError("replayed event")
        if action["task_revision"] != self.revision:
            raise RuntimeModelError("stale task revision")
        if action["session_id"] != self.session_id or action["worktree_digest"] != self.worktree_digest:
            raise RuntimeModelError("crossed execution binding")
        if action["worker_id"] != self.worker_id or action["lease_id"] != self.lease_id:
            raise RuntimeModelError("worker or lease fence mismatch")
        operation = action["operation"]
        if action["authority"] != AUTHORITIES.get(operation):
            raise RuntimeModelError("authority mismatch")
        if set(action["payload"]) != PAYLOAD_FIELDS.get(operation, set()):
            raise RuntimeModelError("unknown or incomplete operation fields")
        if (self.state, operation) not in TRANSITIONS:
            raise RuntimeModelError("invalid lifecycle transition")
        self._validate_payload(operation, action["payload"])
        target = TRANSITIONS[(self.state, operation)]
        if operation == "checkpoint":
            self.checkpoint_digest = action["payload"]["checkpoint_digest"]
        elif operation == "recover":
            if action["payload"]["checkpoint_digest"] != self.checkpoint_digest:
                raise RuntimeModelError("recovery checkpoint mismatch")
            if action["payload"]["new_worker"] == self.worker_id or action["payload"]["new_lease"] == self.lease_id:
                raise RuntimeModelError("recovery must fence worker and lease")
            self.worker_id = action["payload"]["new_worker"]
            self.lease_id = action["payload"]["new_lease"]
        elif operation == "resume" and action["payload"]["checkpoint_digest"] != self.checkpoint_digest:
            raise RuntimeModelError("resume checkpoint mismatch")
        self.state = target
        self.event_ids.add(action["event_id"])
        return self.state

    def _validate_payload(self, operation, payload):
        digest_fields = {"worktree_digest", "claim_digest", "operation_digest", "admission_digest", "decision_digest", "checkpoint_digest", "reason_digest", "head_digest", "observation_digest", "failure_digest"}
        for key, value in payload.items():
            if key in digest_fields and (not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71):
                raise RuntimeModelError("malformed digest")
        if operation == "admit" and payload["revision"] != self.revision:
            raise RuntimeModelError("admission revision mismatch")
        if operation == "oracle_required" and payload["admission_status"] != "not_decided":
            raise RuntimeModelError("runtime cannot manufacture oracle admission")
        if operation == "oracle_answer" and payload["decision"] not in {"approved", "rejected"}:
            raise RuntimeModelError("invalid oracle decision")
        if operation == "publish" and payload["merge_status"] != "not_performed" or operation == "publish" and payload["publication_status"] != "not_performed":
            raise RuntimeModelError("publication side effect claimed")
        if operation == "reconcile" and payload["reconciled"] is not True:
            raise RuntimeModelError("reconciliation not observed")
        if operation == "complete" and payload["completion_observed"] is not True:
            raise RuntimeModelError("completion not observed")

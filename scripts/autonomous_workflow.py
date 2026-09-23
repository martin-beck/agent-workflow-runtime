#!/usr/bin/env python3
"""Offline reference model for the AR-0023 autonomous workflow contract."""

import hashlib
import json
import re


TASK = {"id": "AR-0023", "revision": 1}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^[A-Z][A-Z0-9-]{1,63}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output|command|executable", re.I)


class WorkflowError(ValueError):
    """Raised when an offline workflow observation is not admissible."""


TRANSITIONS = {
    ("new", "plan_observed"): "planned",
    ("planned", "execution_started"): "executing",
    ("executing", "quality_submitted"): "quality_pending",
    ("quality_pending", "oracle_discussion"): "oracle_pending",
    ("oracle_pending", "oracle_decision"): "oracle_observed",
    ("oracle_observed", "checkpoint"): "checkpointed",
    ("checkpointed", "interrupt"): "interrupted",
    ("interrupted", "recover"): "recovering",
    ("recovering", "resume"): "executing",
    ("executing", "review_observed"): "review_pending",
    ("review_pending", "merge_observed"): "merge_pending",
    ("merge_pending", "durable_observation"): "observed",
    ("observed", "reconcile"): "reconciled",
    ("reconciled", "terminal_observation"): "terminal",
}

AUTHORITIES = {
    "plan_observed": "coordinator", "execution_started": "runtime",
    "quality_submitted": "awq", "oracle_discussion": "awg",
    "oracle_decision": "awg", "checkpoint": "runtime", "interrupt": "runtime",
    "recover": "coordinator", "resume": "runtime", "review_observed": "coordinator",
    "merge_observed": "coordinator", "durable_observation": "coordinator",
    "reconcile": "coordinator", "terminal_observation": "coordinator",
}

PAYLOAD_FIELDS = {
    "plan_observed": {"plan_digest", "plan_status"},
    "execution_started": {"execution_digest"},
    "quality_submitted": {"evidence_digest", "quality_status"},
    "oracle_discussion": {"discussion_digest", "oracle_status"},
    "oracle_decision": {"decision_digest", "decision_status"},
    "checkpoint": {"checkpoint_digest", "checkpoint_status"},
    "interrupt": {"reason_digest", "interrupt_status"},
    "recover": {"checkpoint_digest", "new_worker", "new_lease", "recovery_status"},
    "resume": {"checkpoint_digest", "resume_status"},
    "review_observed": {"review_digest", "review_status"},
    "merge_observed": {"merge_digest", "merge_status", "remote_verification"},
    "durable_observation": {"observation_digest", "durable_state"},
    "reconcile": {"reconciliation_digest", "reconciled"},
    "terminal_observation": {"terminal_status", "remote_verification"},
}


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(PRIVATE.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


class WorkflowState:
    def __init__(self, revision, session_id, worktree_digest, worker_id, lease_id):
        self.revision = revision
        self.session_id = session_id
        self.worktree_digest = worktree_digest
        self.worker_id = worker_id
        self.lease_id = lease_id
        self.state = "new"
        self.checkpoint_digest = None
        self.events = set()

    def apply(self, event):
        if event["event_id"] in self.events:
            raise WorkflowError("replayed event")
        if event["task_revision"] != self.revision:
            raise WorkflowError("stale task revision")
        if event["session_id"] != self.session_id or event["worktree_digest"] != self.worktree_digest:
            raise WorkflowError("crossed workflow binding")
        if event["worker_id"] != self.worker_id or event["lease_id"] != self.lease_id:
            raise WorkflowError("worker or lease fence mismatch")
        operation = event["operation"]
        if event["authority"] != AUTHORITIES.get(operation):
            raise WorkflowError("authority mismatch")
        payload = event["payload"]
        if set(payload) != PAYLOAD_FIELDS.get(operation, set()):
            raise WorkflowError("unknown or incomplete operation fields")
        if (self.state, operation) not in TRANSITIONS:
            raise WorkflowError("invalid workflow order")
        if not _safe(event):
            raise WorkflowError("privacy-bearing observation")
        self._payload(operation, payload)
        if operation == "checkpoint":
            self.checkpoint_digest = payload["checkpoint_digest"]
        elif operation == "recover":
            if payload["checkpoint_digest"] != self.checkpoint_digest:
                raise WorkflowError("recovery checkpoint mismatch")
            if payload["new_worker"] == self.worker_id or payload["new_lease"] == self.lease_id:
                raise WorkflowError("recovery did not fence old worker")
            self.worker_id, self.lease_id = payload["new_worker"], payload["new_lease"]
        elif operation == "resume" and payload["checkpoint_digest"] != self.checkpoint_digest:
            raise WorkflowError("resume checkpoint mismatch")
        self.state = TRANSITIONS[(self.state, operation)]
        self.events.add(event["event_id"])
        return self.state

    def _payload(self, operation, payload):
        for key, value in payload.items():
            if key.endswith("digest") and (not isinstance(value, str) or not DIGEST.fullmatch(value)):
                raise WorkflowError("malformed digest")
        if operation == "plan_observed" and payload["plan_status"] != "observed":
            raise WorkflowError("invalid plan status")
        if operation == "quality_submitted" and payload["quality_status"] != "submitted_for_review":
            raise WorkflowError("runtime cannot manufacture quality acceptance")
        if operation == "oracle_discussion" and payload["oracle_status"] != "discussion_requested":
            raise WorkflowError("invalid oracle discussion status")
        if operation == "oracle_decision" and payload["decision_status"] not in {"approved", "rejected"}:
            raise WorkflowError("invalid oracle decision")
        if operation == "merge_observed" and (payload["merge_status"] != "not_performed" or payload["remote_verification"] != "unverified"):
            raise WorkflowError("remote merge success claimed")
        if operation == "terminal_observation" and payload["remote_verification"] != "unverified":
            raise WorkflowError("remote success claimed")
        if operation == "durable_observation" and payload["durable_state"] != "observed":
            raise WorkflowError("durable state mutation claimed")
        if operation == "reconcile" and payload["reconciled"] is not True:
            raise WorkflowError("reconciliation not observed")

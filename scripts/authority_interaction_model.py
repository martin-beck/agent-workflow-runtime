#!/usr/bin/env python3
"""Offline finite-state model for the mandatory AWC/AWR/AWQ/AWG gates.

This is deliberately a small reference model.  It accepts observations and
does not contact an authority, launch an agent, or perform any side effect.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from itertools import product
from typing import Any


class AuthorityModelError(ValueError):
    """A fail-closed transition or binding violation."""


ACTIVE = {
    "new", "admitted", "leased", "dispatched", "executing", "quality_pending",
    "quality_accepted", "oracle_pending", "repair_pending", "ui_pending", "completion_pending", "recovering",
}
TERMINAL = {"completed", "blocked"}
AUTHORITIES = {"admit": "awc", "lease": "awc", "recover": "awc", "commit": "awc",
               "dispatch": "awr", "start": "awr", "evidence": "awr", "continue": "awr",
               "alternative": "awr", "checkpoint": "awr", "crash": "awr", "failure": "awr",
               "retry": "awr", "block": "awr", "quality_accept": "awq",
               "quality_reject": "awq", "quality_unknown": "awq", "guidance_decide": "awg",
               "request_completion": "awr", "repair_escalate": "awr", "ui_decide": "ui"}
PAYLOAD_FIELDS = {
    "admit": {"admitted", "revision", "admission_digest"},
    "lease": {"new_lease_id", "lease_digest"},
    "dispatch": {"admission_digest", "dispatch_digest"},
    "start": {"start_digest"},
    "evidence": {"evidence_digest"},
    "quality_accept": {"evidence_digest", "result", "source"},
    "quality_reject": {"evidence_digest", "result", "source"},
    "quality_unknown": {"evidence_digest", "result", "source"},
    "alternative": {"alternative_digest", "reason", "change_kind"},
    "guidance_decide": {"decision_digest", "decision", "source"},
    "ui_decide": {"decision_digest", "decision", "outcome", "source"},
    "continue": {"quality_digest"},
    "checkpoint": {"checkpoint_digest"},
    "crash": {"checkpoint_digest", "reason"},
    "recover": {"checkpoint_digest", "new_lease_id", "new_revision"},
    "failure": {"failure_digest", "retryable"},
    "retry": {"failure_digest", "new_attempt"},
    "block": {"disposition", "reason_digest"},
    "repair_escalate": {"repair_digest", "reason", "bounded_attempts"},
    "request_completion": {"quality_digest"},
    "commit": {"commit_digest", "terminal"},
}
DIGEST_FIELDS = {field for fields in PAYLOAD_FIELDS.values() for field in fields if field.endswith("digest") or field in {"new_lease_id"}}
VALID_DISPOSITIONS = {"blocked", "pending", "unknown"}
USER_DECISION_CHANGE_KINDS = {"refinement", "test_change", "specification_change", "repair_escalation"}
PRIVATE_WORDS = ("credential", "password", "secret", "token", "prompt", "transcript",
                "private_path", "host_identifier", "raw_output", "llm")


def _digest(value: str) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(
        char in "0123456789abcdef" for char in value[7:]
    )


def _private(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_private(key) or _private(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_private(child) for child in value)
    return isinstance(value, str) and any(word in value.lower() for word in PRIVATE_WORDS)


@dataclass
class JobState:
    job_id: str
    revision: int = 1
    state: str = "new"
    lease_id: str = ""
    checkpoint_digest: str | None = None
    evidence_digest: str | None = None
    quality_status: str = "not_decided"
    guidance_status: str = "not_required"
    ui_status: str = "not_required"
    material_alternative: bool = False
    user_decision_required: bool = False
    repair_required: bool = False
    terminal_commit: bool = False
    attempt: int = 0


@dataclass
class InteractionModel:
    """Multiple independent jobs sharing one deterministic transition model."""

    jobs: dict[str, JobState] = field(default_factory=dict)
    event_ids: set[str] = field(default_factory=set)

    def clone(self) -> InteractionModel:
        return deepcopy(self)

    def add_job(self, job_id: str) -> None:
        if not isinstance(job_id, str) or not job_id.startswith("JOB-") or job_id in self.jobs:
            raise AuthorityModelError("invalid or duplicate job")
        self.jobs[job_id] = JobState(job_id)

    def apply(self, action: dict[str, Any]) -> str:
        required = {"action_id", "sequence", "job_id", "authority", "operation", "task_revision", "lease_id", "payload"}
        if not isinstance(action, dict) or set(action) != required:
            raise AuthorityModelError("malformed action")
        if action["action_id"] in self.event_ids:
            raise AuthorityModelError("replayed action")
        job = self.jobs.get(action["job_id"])
        if job is None:
            raise AuthorityModelError("unknown job")
        if action["task_revision"] != job.revision:
            raise AuthorityModelError("stale task revision")
        operation = action["operation"]
        if action["authority"] != AUTHORITIES.get(operation):
            raise AuthorityModelError("authority mismatch")
        if operation not in PAYLOAD_FIELDS or not isinstance(action["payload"], dict) or set(action["payload"]) != PAYLOAD_FIELDS[operation]:
            raise AuthorityModelError("unknown or incomplete operation fields")
        if operation not in {"admit", "lease"} and action["lease_id"] != job.lease_id:
            raise AuthorityModelError("lease fence mismatch")
        if operation in {"admit", "lease"} and action["lease_id"] != job.lease_id:
            raise AuthorityModelError("pre-lease fence mismatch")
        if _private(action):
            raise AuthorityModelError("privacy-bearing action")
        self._validate_payload(job, operation, action["payload"])
        self._transition(job, operation, action["payload"])
        self.event_ids.add(action["action_id"])
        return job.state

    def _validate_payload(self, job: JobState, operation: str, payload: dict[str, Any]) -> None:
        for name, value in payload.items():
            if name.endswith("digest") and not (operation == "ui_decide" and name == "decision_digest" and value is None) and not _digest(value):
                raise AuthorityModelError("malformed digest")
        if operation == "admit" and (payload["admitted"] is not True or payload["revision"] != job.revision):
            raise AuthorityModelError("missing AWC admission")
        if operation == "lease" and (not isinstance(payload["new_lease_id"], str) or not payload["new_lease_id"].startswith("LSE-") or payload["new_lease_id"] == job.lease_id):
            raise AuthorityModelError("invalid lease")
        if operation == "dispatch" and job.state != "leased":
            raise AuthorityModelError("dispatch without AWC admission and lease")
        if operation == "quality_accept" and (payload["result"] != "accepted" or payload["source"] != "awq" or payload["evidence_digest"] != job.evidence_digest):
            raise AuthorityModelError("invalid AWQ acceptance")
        if operation in {"quality_reject", "quality_unknown"} and (payload["source"] != "awq" or payload["result"] not in {"rejected", "unknown"}):
            raise AuthorityModelError("invalid AWQ result")
        if operation == "guidance_decide" and (payload["source"] != "awg" or payload["decision"] not in {"approved", "rejected", "requires_ui"}):
            raise AuthorityModelError("invalid AWG decision")
        if operation == "guidance_decide" and job.user_decision_required and payload["decision"] != "requires_ui":
            raise AuthorityModelError("AWG must route required user decision to UI")
        if operation == "ui_decide":
            if payload["source"] != "ui" or payload["outcome"] not in {"approved", "rejected", "ambiguous", "expired"}:
                raise AuthorityModelError("invalid UI decision outcome")
            if payload["outcome"] == "approved" and (payload["decision"] != "approved" or not _digest(payload["decision_digest"])):
                raise AuthorityModelError("UI approval lacks attributed decision")
            if payload["outcome"] != "approved" and (payload["decision"] != "unresolved" or payload["decision_digest"] is not None):
                raise AuthorityModelError("unresolved UI outcome cannot approve")
        if operation == "continue" and (job.quality_status != "accepted" or job.guidance_status == "pending" or job.ui_status == "pending" or job.material_alternative):
            raise AuthorityModelError("continuation without mandatory authority gates")
        if operation == "request_completion" and (job.quality_status != "accepted" or job.material_alternative or job.guidance_status == "pending" or job.ui_status == "pending"):
            raise AuthorityModelError("completion request without mandatory gates")
        if operation == "commit" and (job.state != "completion_pending" or payload["terminal"] is not True):
            raise AuthorityModelError("completion without AWC terminal commit")
        if operation == "recover" and payload["new_revision"] != job.revision + 1:
            raise AuthorityModelError("recovery revision must advance")
        if operation == "block" and payload["disposition"] not in VALID_DISPOSITIONS:
            raise AuthorityModelError("invalid fail-closed disposition")
        if operation == "alternative" and payload["change_kind"] not in USER_DECISION_CHANGE_KINDS | {"ordinary_alternative"}:
            raise AuthorityModelError("invalid material change kind")
        if operation == "repair_escalate" and (payload["reason"] != "bounded_repair_exhausted" or not isinstance(payload["bounded_attempts"], int) or payload["bounded_attempts"] < 1):
            raise AuthorityModelError("repair escalation is not bounded")
        if operation == "retry" and not job.lease_id:
            raise AuthorityModelError("retry without AWC lease")

    def _transition(self, job: JobState, operation: str, payload: dict[str, Any]) -> None:
        state = job.state
        allowed = {
            ("new", "admit"): "admitted", ("admitted", "lease"): "leased",
            ("leased", "dispatch"): "dispatched", ("dispatched", "start"): "executing",
            ("executing", "evidence"): "quality_pending", ("quality_pending", "quality_accept"): "quality_accepted",
            ("quality_pending", "quality_reject"): "blocked", ("quality_pending", "quality_unknown"): "blocked",
            ("quality_accepted", "alternative"): "oracle_pending", ("oracle_pending", "guidance_decide"): "quality_accepted",
            ("executing", "repair_escalate"): "repair_pending", ("quality_accepted", "repair_escalate"): "repair_pending", ("repair_pending", "guidance_decide"): "ui_pending",
            ("ui_pending", "ui_decide"): "quality_accepted",
            ("quality_accepted", "continue"): "executing", ("quality_accepted", "request_completion"): "completion_pending", ("executing", "request_completion"): "completion_pending",
            ("completion_pending", "commit"): "completed", ("executing", "checkpoint"): "executing",
            ("executing", "crash"): "recovering", ("recovering", "recover"): "leased",
            ("executing", "failure"): "blocked", ("blocked", "retry"): "executing",
        }
        if (state, operation) not in allowed and not (operation == "block" and state in ACTIVE):
            raise AuthorityModelError("invalid lifecycle transition")
        if operation == "lease": job.lease_id = payload["new_lease_id"]
        elif operation == "evidence": job.evidence_digest = payload["evidence_digest"]
        elif operation == "quality_accept": job.quality_status = "accepted"
        elif operation in {"quality_reject", "quality_unknown"}: job.quality_status = payload["result"]
        elif operation == "alternative":
            job.material_alternative, job.guidance_status = True, "pending"
            job.user_decision_required = payload["change_kind"] in USER_DECISION_CHANGE_KINDS
        elif operation == "repair_escalate":
            job.material_alternative, job.guidance_status, job.user_decision_required, job.repair_required = True, "pending", True, True
        elif operation == "guidance_decide":
            if payload["decision"] == "requires_ui":
                job.guidance_status, job.ui_status = "requires_ui", "pending"
            else:
                job.material_alternative = False
                job.guidance_status = payload["decision"]
        elif operation == "ui_decide":
            job.ui_status = payload["outcome"]
            if payload["outcome"] == "approved":
                job.material_alternative, job.guidance_status, job.user_decision_required = False, "approved", False
                if job.repair_required:
                    job.repair_required = False
                    job.state = "executing"
            else:
                job.state = "blocked"
        elif operation == "checkpoint": job.checkpoint_digest = payload["checkpoint_digest"]
        elif operation == "recover":
            if payload["checkpoint_digest"] != job.checkpoint_digest:
                raise AuthorityModelError("recovery checkpoint mismatch")
            job.revision, job.lease_id, job.attempt = payload["new_revision"], payload["new_lease_id"], job.attempt + 1
        elif operation == "retry": job.attempt += 1
        elif operation == "commit": job.terminal_commit = True
        if ((operation == "ui_decide" and payload["outcome"] != "approved") or
                (operation == "guidance_decide" and payload["decision"] == "rejected")):
            job.state = "blocked"
        elif operation == "guidance_decide" and payload["decision"] == "requires_ui":
            job.state = "ui_pending"
        else:
            job.state = allowed.get((state, operation), "blocked")

    def invariants(self) -> list[str]:
        violations = []
        for job in self.jobs.values():
            if job.state in {"dispatched", "executing", "quality_pending", "quality_accepted", "oracle_pending", "repair_pending", "ui_pending", "completion_pending", "completed"} and (not job.lease_id or job.revision < 1):
                violations.append(job.job_id + ":dispatch_without_awc_lease")
            if job.state in {"quality_accepted", "oracle_pending", "completion_pending", "completed"} and job.quality_status != "accepted":
                violations.append(job.job_id + ":continuation_without_awq_acceptance")
            if job.state in {"completion_pending", "completed"} and (job.material_alternative or job.ui_status == "pending"):
                violations.append(job.job_id + ":material_alternative_without_awg_decision")
            if job.state == "completed" and not job.terminal_commit:
                violations.append(job.job_id + ":completion_without_awc_commit")
        return violations


REFINEMENT_EVENTS = {
    "admitted": "admit", "queued": "lease", "running": "dispatch", "checkpointed": "checkpoint",
    "retry_queued": "retry", "succeeded": "commit", "failed": "failure", "scheduled": "lease",
    "assigned": "dispatch", "executing": "start", "observed": "evidence", "quality_pending": "evidence",
    "oracle_pending": "alternative", "accepted": "commit", "rejected": "quality_reject",
}


def refine_event(kind: str) -> str:
    """Map executable scheduler/contractor observations to model operations."""
    try:
        return REFINEMENT_EVENTS[kind]
    except KeyError as exc:
        raise AuthorityModelError("unmapped runtime event") from exc


def bounded_model_check(max_depth: int = 4, job_ids: tuple[str, ...] = ("JOB-A", "JOB-B")) -> dict[str, int]:
    """Explore all operation/job interleavings up to *max_depth*.

    Invalid candidates are deliberately ignored as hostile inputs; every
    accepted prefix must satisfy all safety invariants.  Tests separately
    exercise each omitted-gate edge with malformed/hostile actions.
    """
    if max_depth < 1 or max_depth > 8 or not job_ids:
        raise AuthorityModelError("invalid bounded-check limit")
    initial = InteractionModel()
    for job_id in job_ids: initial.add_job(job_id)
    frontier = [(initial, 0)]
    explored = 0
    accepted = 0
    while frontier:
        model, depth = frontier.pop()
        explored += 1
        if model.invariants(): raise AuthorityModelError("invariant violated during bounded exploration")
        if depth == max_depth: continue
        for job_id, operation in product(job_ids, AUTHORITIES):
            candidate = model.clone()
            action = canonical_candidate(candidate.jobs[job_id], operation, f"BMC-{explored}-{job_id}-{operation}", depth + 1)
            try:
                candidate.apply(action)
            except AuthorityModelError:
                continue
            accepted += 1
            frontier.append((candidate, depth + 1))
    return {"max_depth": max_depth, "jobs": len(job_ids), "states": explored, "accepted_edges": accepted}


def canonical_candidate(job: JobState, operation: str, action_id: str, sequence: int) -> dict[str, Any]:
    digest = "sha256:" + "0" * 64
    payload = {key: digest for key in PAYLOAD_FIELDS.get(operation, ())}
    if operation == "admit": payload.update(admitted=True, revision=job.revision)
    elif operation == "lease": payload.update(new_lease_id=f"LSE-{job.job_id}-B", lease_digest=digest)
    elif operation == "quality_accept": payload.update(result="accepted", source="awq", evidence_digest=job.evidence_digest or digest)
    elif operation in {"quality_reject", "quality_unknown"}: payload.update(result="rejected" if operation == "quality_reject" else "unknown", source="awq")
    elif operation == "alternative": payload.update(reason="bounded uncertainty", change_kind="ordinary_alternative")
    elif operation == "repair_escalate": payload.update(reason="bounded_repair_exhausted", bounded_attempts=1)
    elif operation == "guidance_decide": payload.update(decision="approved", source="awg")
    elif operation == "ui_decide": payload.update(decision="approved", outcome="approved", source="ui")
    elif operation == "recover": payload.update(new_lease_id=f"LSE-{job.job_id}-R", new_revision=job.revision + 1)
    elif operation == "failure": payload["retryable"] = True
    elif operation == "retry": payload["new_attempt"] = job.attempt + 1
    elif operation == "block": payload.update(disposition="blocked")
    elif operation == "commit": payload["terminal"] = True
    lease = job.lease_id
    return {"action_id": action_id, "sequence": sequence, "job_id": job.job_id, "authority": AUTHORITIES.get(operation, "awr"), "operation": operation, "task_revision": job.revision, "lease_id": lease, "payload": payload}

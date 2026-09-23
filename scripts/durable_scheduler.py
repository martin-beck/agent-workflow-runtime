#!/usr/bin/env python3
"""Deterministic durable scheduler and worker-lease reference model.

This is an offline kernel.  It models the decisions and fences which a real
Coordinator-backed runtime must enforce; it does not persist, execute, or
contact a worker, provider, network, or service.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any


class SchedulerError(ValueError):
    pass


TERMINAL = {"succeeded", "failed", "cancelled"}
RETRYABLE = {"worker_lost", "transient_unavailable", "lease_expired"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=lambda item: asdict(item) if is_dataclass(item) else sorted(item) if isinstance(item, (set, frozenset)) else str(item)).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


@dataclass(frozen=True)
class Resources:
    cpu: int = 1
    memory: int = 1
    disk: int = 1

    def __post_init__(self):
        if any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in (self.cpu, self.memory, self.disk)):
            raise SchedulerError("resources must be non-negative integers")

    def fits(self, available: Resources) -> bool:
        return self.cpu <= available.cpu and self.memory <= available.memory and self.disk <= available.disk

    def add(self, other: Resources) -> Resources:
        return Resources(self.cpu + other.cpu, self.memory + other.memory, self.disk + other.disk)

    def subtract(self, other: Resources) -> Resources:
        return Resources(self.cpu - other.cpu, self.memory - other.memory, self.disk - other.disk)


@dataclass
class Job:
    job_id: str
    dependencies: tuple[str, ...] = ()
    priority: int = 50
    tenant: str = "default"
    resources: Resources = field(default_factory=Resources)
    max_attempts: int = 1
    retryable: frozenset[str] = frozenset(RETRYABLE)
    deadline: int | None = None
    idempotency_key: str | None = None
    state: str = "submitted"
    submitted_at: int = 0
    queued_at: int | None = None
    attempts: int = 0
    lease_id: str | None = None
    worker_id: str | None = None
    lease_expires: int | None = None
    checkpoint: str | None = None
    cancel_requested: bool = False
    retry_at: int | None = None
    failure_reason: str | None = None


@dataclass(frozen=True)
class Lease:
    lease_id: str
    job_id: str
    worker_id: str
    expires_at: int
    fence: int
    resources: Resources


class Scheduler:
    """A deterministic, single-threaded model of the durable scheduling kernel."""

    def __init__(self, capacity: Resources, *, max_concurrency: int, max_queued: int = 1024,
                 lease_seconds: int = 30, tenant_limits: dict[str, int] | None = None,
                 aging_quantum: int = 10):
        if max_concurrency < 1 or max_queued < 0 or lease_seconds < 1 or aging_quantum < 1:
            raise SchedulerError("invalid scheduler limits")
        self.capacity = capacity
        self.available = capacity
        self.max_concurrency = max_concurrency
        self.max_queued = max_queued
        self.lease_seconds = lease_seconds
        self.tenant_limits = dict(tenant_limits or {})
        self.aging_quantum = aging_quantum
        self.jobs: dict[str, Job] = {}
        self.leases: dict[str, Lease] = {}
        self.events: list[dict[str, Any]] = []
        self.operations: dict[str, tuple[str, Any]] = {}
        self.fence = 0
        self.now = 0

    def _op(self, operation_id: str, request: Any) -> Any | None:
        key = digest(request)
        old = self.operations.get(operation_id)
        if old:
            if old[0] != key:
                raise SchedulerError("idempotency conflict")
            return old[1]
        return None

    def _remember(self, operation_id: str, request: Any, result: Any) -> Any:
        self.operations[operation_id] = (digest(request), result)
        return result

    def _event(self, operation_id: str, kind: str, job_id: str, **extra: Any) -> dict[str, Any]:
        event = {"sequence": len(self.events) + 1, "operation_id": operation_id, "kind": kind, "job_id": job_id, **extra}
        self.events.append(event)
        return event

    def _queued_count(self) -> int:
        return sum(job.state == "queued" for job in self.jobs.values())

    def _validate_job(self, job: Job) -> None:
        if not job.job_id or job.job_id in self.jobs or job.priority < 0 or job.priority > 100:
            raise SchedulerError("invalid or duplicate job")
        if job.max_attempts < 1 or job.deadline is not None and job.deadline < self.now:
            raise SchedulerError("invalid attempts or deadline")
        if len(set(job.dependencies)) != len(job.dependencies) or job.job_id in job.dependencies:
            raise SchedulerError("invalid dependencies")
        if any(dep not in self.jobs for dep in job.dependencies):
            raise SchedulerError("unknown dependency")

    def admit(self, operation_id: str, job: Job) -> str:
        request = {"job": job.__dict__}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        self._validate_job(job)
        self.jobs[job.job_id] = job
        self._event(operation_id, "admitted", job.job_id)
        return self._remember(operation_id, request, job.job_id)

    def release_dependencies(self, now: int) -> list[str]:
        self.now = max(self.now, now)
        released = []
        for job in self.jobs.values():
            if job.state != "submitted":
                continue
            deps = [self.jobs[dep] for dep in job.dependencies]
            if any(dep.state == "failed" or dep.state == "cancelled" for dep in deps):
                job.state, job.failure_reason = "failed", "dependency_terminal_failure"
                self._event("reconcile-" + job.job_id, "failed", job.job_id, reason=job.failure_reason)
            elif all(dep.state == "succeeded" for dep in deps):
                if self._queued_count() >= self.max_queued:
                    continue
                job.state, job.queued_at = "queued", self.now
                released.append(job.job_id)
                self._event("release-" + job.job_id, "queued", job.job_id)
        return released

    def _score(self, job: Job) -> tuple[int, int, str]:
        waited = max(0, self.now - (job.queued_at if job.queued_at is not None else self.now))
        # Aging is bounded into the primary score and job ID breaks all ties.
        return (job.priority + waited // self.aging_quantum, -job.queued_at, job.job_id)

    def _tenant_running(self, tenant: str) -> int:
        return sum(j.state == "running" and j.tenant == tenant for j in self.jobs.values())

    def dispatch(self, operation_id: str, worker_id: str, now: int) -> Lease | None:
        self.now = max(self.now, now)
        request = {"worker": worker_id, "now": now}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        if not worker_id or sum(j.state == "running" for j in self.jobs.values()) >= self.max_concurrency:
            return self._remember(operation_id, request, None)
        self.release_dependencies(self.now)
        candidates = []
        for job in self.jobs.values():
            if job.state != "queued" or (job.retry_at is not None and self.now < job.retry_at):
                continue
            if job.deadline is not None and self.now > job.deadline:
                job.state, job.failure_reason = "failed", "deadline_exceeded"
                self._event("deadline-" + job.job_id, "failed", job.job_id, reason=job.failure_reason)
                continue
            if self.tenant_limits.get(job.tenant, self.max_concurrency) <= self._tenant_running(job.tenant):
                continue
            if not job.resources.fits(self.available):
                continue
            candidates.append(job)
        if not candidates:
            return self._remember(operation_id, request, None)
        job = max(candidates, key=self._score)
        self.fence += 1
        lease = Lease(f"LSE-{job.job_id}-{self.fence}", job.job_id, worker_id, self.now + self.lease_seconds, self.fence, job.resources)
        job.state, job.attempts = "running", job.attempts + 1
        job.lease_id, job.worker_id, job.lease_expires, job.retry_at = lease.lease_id, worker_id, lease.expires_at, None
        self.leases[job.job_id] = lease
        self.available = self.available.subtract(job.resources)
        self._event(operation_id, "running", job.job_id, lease_id=lease.lease_id, fence=lease.fence)
        return self._remember(operation_id, request, lease)

    def _owned(self, job_id: str, worker_id: str, lease_id: str, now: int) -> Job:
        job = self.jobs.get(job_id)
        lease = self.leases.get(job_id)
        if not job or not lease or job.state != "running" or lease.worker_id != worker_id or lease.lease_id != lease_id or now >= lease.expires_at:
            raise SchedulerError("stale, unknown, or expired lease")
        self.now = max(self.now, now)
        return job

    def heartbeat(self, operation_id: str, job_id: str, worker_id: str, lease_id: str, now: int) -> Lease:
        request = {"job_id": job_id, "worker": worker_id, "lease": lease_id, "now": now}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        job = self._owned(job_id, worker_id, lease_id, now)
        old = self.leases[job_id]
        lease = Lease(old.lease_id, old.job_id, old.worker_id, now + self.lease_seconds, old.fence, old.resources)
        self.leases[job_id], job.lease_expires = lease, lease.expires_at
        self._event(operation_id, "heartbeat", job_id, lease_id=lease_id, expires_at=lease.expires_at)
        return self._remember(operation_id, request, lease)

    def checkpoint(self, operation_id: str, job_id: str, worker_id: str, lease_id: str, checkpoint_digest: str, now: int) -> str:
        request = {"job_id": job_id, "worker": worker_id, "lease": lease_id, "checkpoint": checkpoint_digest, "now": now}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        if not isinstance(checkpoint_digest, str) or not checkpoint_digest.startswith("sha256:"):
            raise SchedulerError("invalid checkpoint digest")
        job = self._owned(job_id, worker_id, lease_id, now)
        job.checkpoint = checkpoint_digest
        self._event(operation_id, "checkpointed", job_id, checkpoint=checkpoint_digest)
        return self._remember(operation_id, request, checkpoint_digest)

    def complete(self, operation_id: str, job_id: str, worker_id: str, lease_id: str, now: int) -> str:
        request = {"job_id": job_id, "worker": worker_id, "lease": lease_id, "now": now, "state": "succeeded"}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        job = self._owned(job_id, worker_id, lease_id, now)
        self._release(job)
        job.state = "succeeded"
        self._event(operation_id, "succeeded", job_id)
        return self._remember(operation_id, request, job.state)

    def fail(self, operation_id: str, job_id: str, worker_id: str, lease_id: str, reason: str, now: int) -> str:
        request = {"job_id": job_id, "worker": worker_id, "lease": lease_id, "reason": reason, "now": now}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        job = self._owned(job_id, worker_id, lease_id, now)
        self._release(job)
        job.failure_reason = reason
        if reason in job.retryable and job.attempts < job.max_attempts:
            job.state, job.retry_at = "queued", now + min(60, 2 ** (job.attempts - 1))
            job.queued_at = now
            self._event(operation_id, "retry_queued", job_id, retry_at=job.retry_at, attempt=job.attempts)
        else:
            job.state = "failed"
            self._event(operation_id, "failed", job_id, reason=reason)
        return self._remember(operation_id, request, job.state)

    def request_cancel(self, operation_id: str, job_id: str, now: int) -> str:
        request = {"job_id": job_id, "now": now}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        job = self.jobs.get(job_id)
        if not job or job.state in TERMINAL:
            raise SchedulerError("unknown or terminal job")
        job.cancel_requested = True
        if job.state == "queued":
            job.state = "cancelled"
            self._event(operation_id, "cancelled", job_id)
        else:
            job.state = "cancelling"
            self._event(operation_id, "cancelling", job_id)
        return self._remember(operation_id, request, job.state)

    def acknowledge_cancel(self, operation_id: str, job_id: str, worker_id: str, lease_id: str, now: int) -> str:
        request = {"job_id": job_id, "worker": worker_id, "lease": lease_id, "now": now}
        replay = self._op(operation_id, request)
        if replay is not None:
            return replay
        job = self._owned(job_id, worker_id, lease_id, now)
        if not job.cancel_requested or job.state != "cancelling":
            raise SchedulerError("cancellation not requested")
        self._release(job)
        job.state = "cancelled"
        self._event(operation_id, "cancelled", job_id)
        return self._remember(operation_id, request, job.state)

    def expire(self, now: int) -> list[str]:
        self.now = max(self.now, now)
        expired = []
        for job in list(self.jobs.values()):
            lease = self.leases.get(job.job_id)
            if job.state == "running" and lease and now >= lease.expires_at:
                self._release(job)
                expired.append(job.job_id)
                if job.attempts < job.max_attempts:
                    job.state, job.retry_at, job.queued_at = "queued", now, now
                    job.failure_reason = "lease_expired"
                    self._event("expire-" + job.job_id, "retry_queued", job.job_id, attempt=job.attempts)
                else:
                    job.state, job.failure_reason = "failed", "lease_expired"
                    self._event("expire-" + job.job_id, "failed", job.job_id, reason=job.failure_reason)
        return expired

    def _release(self, job: Job) -> None:
        lease = self.leases.pop(job.job_id, None)
        if lease:
            self.available = self.available.add(lease.resources)
        job.lease_id = job.worker_id = job.lease_expires = None

    def reconcile(self) -> dict[str, str]:
        """Return a deterministic terminal projection after dependency release."""
        self.release_dependencies(self.now)
        return {job_id: job.state for job_id, job in sorted(self.jobs.items()) if job.state in TERMINAL}

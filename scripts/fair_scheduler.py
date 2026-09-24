#!/usr/bin/env python3
"""Deterministic multi-tenant scheduler for AR-0086.

This module is a local policy and reservation engine.  It consumes already
validated Coordinator revisions, agent-registry profiles, lease fences, and
adapter-session identities; it does not own or mutate any of those
authorities.  No worker, provider, network, subprocess, or clock service is
used.  ``now`` is supplied by the caller, making every decision replayable.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

PROTOCOL = {"id": "awr-fair-scheduler", "version": "1.0.0"}
TASK = {"id": "AR-0086", "revision": 3}
TERMINAL = {"succeeded", "failed", "cancelled"}
RETRYABLE = frozenset({"worker_lost", "transient_unavailable", "lease_expired"})
ID = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
JOB_ID = re.compile(r"^JOB-[A-Z0-9-]{1,48}$")
LEASE_ID = re.compile(r"^LSE-[A-Z0-9-]{1,63}$")
SESSION_ID = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SchedulingError(ValueError):
    """A fail-closed admission, scheduling, or fenced lifecycle rejection."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default).encode()


def _json_default(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(value)
    raise TypeError(f"unsupported value: {type(value).__name__}")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise SchedulingError(f"invalid_{name}")
    return value


@dataclass(frozen=True)
class Resources:
    cpu: int = 1
    memory: int = 1
    disk: int = 1

    def __post_init__(self) -> None:
        values = (self.cpu, self.memory, self.disk)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
            raise SchedulingError("resources must be non-negative integers")
        if not any(values):
            raise SchedulingError("job resources must not be zero")

    def fits(self, available: Resources) -> bool:
        return self.cpu <= available.cpu and self.memory <= available.memory and self.disk <= available.disk

    def add(self, other: Resources) -> Resources:
        return Resources(self.cpu + other.cpu, self.memory + other.memory, self.disk + other.disk)

    def subtract(self, other: Resources) -> Resources:
        return Resources(self.cpu - other.cpu, self.memory - other.memory, self.disk - other.disk)

    def as_dict(self) -> dict[str, int]:
        return {"cpu": self.cpu, "memory": self.memory, "disk": self.disk}


@dataclass(frozen=True)
class AgentSlot:
    """A supplied, preflighted AR-0084 profile usable by AR-0085 sessions."""

    agent_id: str
    profile_digest: str
    capabilities: frozenset[str] = frozenset()
    capacity: Resources = field(default_factory=Resources)
    max_concurrency: int = 1
    registry_digest: str = ""
    preflight_status: str = "accepted"

    def validate(self) -> None:
        _identifier(self.agent_id, "agent_id")
        if not DIGEST.fullmatch(self.profile_digest):
            raise SchedulingError("invalid_profile_digest")
        if self.registry_digest and not DIGEST.fullmatch(self.registry_digest):
            raise SchedulingError("invalid_registry_digest")
        if self.preflight_status != "accepted":
            raise SchedulingError("agent_preflight_not_accepted")
        if isinstance(self.max_concurrency, bool) or not isinstance(self.max_concurrency, int) or self.max_concurrency < 1:
            raise SchedulingError("invalid_agent_concurrency")
        if not self.capabilities or any(not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", item) for item in self.capabilities):
            raise SchedulingError("invalid_agent_capabilities")


@dataclass
class JobSpec:
    job_id: str
    tenant: str
    project: str
    priority: int = 50
    resources: Resources = field(default_factory=Resources)
    dependencies: tuple[str, ...] = ()
    required_capabilities: frozenset[str] = frozenset()
    eligible_agents: frozenset[str] = frozenset()
    max_attempts: int = 1
    retry_budget: int = 0
    retryable: frozenset[str] = RETRYABLE
    retry_backoff: int = 1
    deadline: int | None = None
    coordinator_revision: int = 1
    registry_digest: str = ""
    state: str = "submitted"
    submitted_at: int = 0
    queued_at: int | None = None
    attempts: int = 0
    retries_used: int = 0
    retry_at: int | None = None
    lease: DispatchLease | None = None  # type: ignore[name-defined]
    failure_reason: str | None = None
    cancel_requested: bool = False


@dataclass(frozen=True)
class DispatchLease:
    job_id: str
    lease_id: str
    agent_id: str
    fence: int
    expires_at: int
    coordinator_revision: int
    profile_digest: str
    session_id: str
    worktree_key: str
    resources: Resources


class FairScheduler:
    """Single-threaded virtual-time scheduler with deterministic fair queuing."""

    def __init__(
        self,
        capacity: Resources,
        *,
        max_concurrency: int,
        max_queued: int = 1024,
        lease_seconds: int = 30,
        aging_quantum: int = 10,
        tenant_quotas: dict[str, int] | None = None,
        project_quotas: dict[str, int] | None = None,
        agent_quotas: dict[str, int] | None = None,
        authority_revision: int = 1,
        registry_digest: str = "",
    ) -> None:
        if max_concurrency < 1 or max_queued < 0 or lease_seconds < 1 or aging_quantum < 1 or authority_revision < 1:
            raise SchedulingError("invalid_scheduler_limits")
        self.capacity = capacity
        self.available = capacity
        self.max_concurrency = max_concurrency
        self.max_queued = max_queued
        self.lease_seconds = lease_seconds
        self.aging_quantum = aging_quantum
        self.authority_revision = authority_revision
        if registry_digest and not DIGEST.fullmatch(registry_digest):
            raise SchedulingError("invalid_registry_digest")
        self.registry_digest = registry_digest
        self.tenant_quotas = self._quota_map(tenant_quotas, "tenant")
        self.project_quotas = self._quota_map(project_quotas, "project")
        self.agent_quotas = self._quota_map(agent_quotas, "agent")
        self.agents: dict[str, AgentSlot] = {}
        self.jobs: dict[str, JobSpec] = {}
        self.operations: dict[str, tuple[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.service: dict[tuple[str, str], int] = {}
        self.agent_service: dict[str, int] = {}
        self.available_agents: dict[str, int] = {}
        self.now = 0
        self.fence = 0

    @staticmethod
    def _quota_map(values: dict[str, int] | None, name: str) -> dict[str, int]:
        result = dict(values or {})
        if any(not isinstance(key, str) or not ID.fullmatch(key) or isinstance(value, bool) or not isinstance(value, int) or value < 1 for key, value in result.items()):
            raise SchedulingError(f"invalid_{name}_quotas")
        return result

    def register_agent(self, profile: AgentSlot) -> None:
        profile.validate()
        if profile.agent_id in self.agents:
            raise SchedulingError("duplicate_agent")
        if profile.registry_digest and self.registry_digest and profile.registry_digest != self.registry_digest:
            raise SchedulingError("registry_digest_mismatch")
        self.agents[profile.agent_id] = profile
        self.available_agents[profile.agent_id] = profile.max_concurrency

    def _remember(self, operation_id: str, request: Any, result: Any) -> Any:
        if not isinstance(operation_id, str) or not operation_id:
            raise SchedulingError("invalid_operation_id")
        fingerprint = digest(request)
        old = self.operations.get(operation_id)
        if old is not None:
            if old[0] != fingerprint:
                raise SchedulingError("idempotency_conflict")
            return old[1]
        self.operations[operation_id] = (fingerprint, result)
        return result

    def _replay(self, operation_id: str, request: Any) -> tuple[bool, Any]:
        old = self.operations.get(operation_id)
        if old is None:
            return False, None
        if old[0] != digest(request):
            raise SchedulingError("idempotency_conflict")
        return True, old[1]

    def _event(self, operation_id: str, kind: str, job_id: str, **details: Any) -> None:
        self.events.append({"sequence": len(self.events) + 1, "operation_id": operation_id, "kind": kind, "job_id": job_id, **details})

    def _active_count(self) -> int:
        return sum(job.state not in TERMINAL for job in self.jobs.values())

    def _running_count(self) -> int:
        return sum(job.state == "running" for job in self.jobs.values())

    def _running_tenant(self, tenant: str) -> int:
        return sum(job.state == "running" and job.tenant == tenant for job in self.jobs.values())

    def _running_project(self, project: str) -> int:
        return sum(job.state == "running" and job.project == project for job in self.jobs.values())

    def _running_agent(self, agent_id: str) -> int:
        return sum(job.state == "running" and job.lease is not None and job.lease.agent_id == agent_id for job in self.jobs.values())

    def _validate_job(self, job: JobSpec) -> None:
        if not JOB_ID.fullmatch(job.job_id) or job.job_id in self.jobs:
            raise SchedulingError("invalid_or_duplicate_job")
        _identifier(job.tenant, "tenant")
        _identifier(job.project, "project")
        if isinstance(job.priority, bool) or not isinstance(job.priority, int) or not 0 <= job.priority <= 100:
            raise SchedulingError("invalid_priority")
        if not job.dependencies or job.dependencies is None:
            dependencies = ()
        else:
            dependencies = tuple(job.dependencies)
        if len(set(dependencies)) != len(dependencies) or job.job_id in dependencies:
            raise SchedulingError("invalid_dependencies")
        if any(not JOB_ID.fullmatch(dep) or dep not in self.jobs for dep in dependencies):
            raise SchedulingError("unknown_dependency")
        if self._would_cycle(job.job_id, dependencies):
            raise SchedulingError("dependency_cycle")
        if job.max_attempts < 1 or job.retry_budget < 0 or job.retry_budget > job.max_attempts - 1 or job.retry_backoff < 1:
            raise SchedulingError("invalid_retry_budget")
        if job.deadline is not None and (isinstance(job.deadline, bool) or not isinstance(job.deadline, int) or job.deadline < self.now):
            raise SchedulingError("invalid_deadline")
        if job.coordinator_revision != self.authority_revision:
            raise SchedulingError("stale_coordinator_revision")
        if self.registry_digest and job.registry_digest != self.registry_digest:
            raise SchedulingError("stale_registry_digest")
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", capability) for capability in job.required_capabilities):
            raise SchedulingError("invalid_capability_requirement")
        if any(agent not in self.agents for agent in job.eligible_agents):
            raise SchedulingError("unknown_eligible_agent")

    def _would_cycle(self, new_job: str, dependencies: tuple[str, ...]) -> bool:
        graph = {job_id: set(job.dependencies) for job_id, job in self.jobs.items()}
        graph[new_job] = set(dependencies)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            if any(visit(dep) for dep in graph.get(node, ())):
                return True
            visiting.remove(node)
            visited.add(node)
            return False

        return any(visit(node) for node in graph)

    def admit(self, operation_id: str, job: JobSpec) -> str:
        request = {"action": "admit", "job": asdict(job)}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        self._validate_job(job)
        if self._active_count() >= self.max_queued:
            raise SchedulingError("backpressure_active_job_limit")
        if self._queued_count(job.tenant) >= self.tenant_quotas.get(job.tenant, self.max_queued):
            raise SchedulingError("tenant_backpressure")
        if self._queued_project_count(job.project) >= self.project_quotas.get(job.project, self.max_queued):
            raise SchedulingError("project_backpressure")
        job.submitted_at = self.now
        self.jobs[job.job_id] = job
        self._event(operation_id, "admitted", job.job_id, tenant=job.tenant, project=job.project)
        return self._remember(operation_id, request, job.job_id)

    def _queued_count(self, tenant: str | None = None) -> int:
        return sum(job.state not in TERMINAL and (tenant is None or job.tenant == tenant) for job in self.jobs.values())

    def _queued_project_count(self, project: str) -> int:
        return sum(job.state not in TERMINAL and job.project == project for job in self.jobs.values())

    def _ready(self) -> None:
        for job in sorted(self.jobs.values(), key=lambda item: item.job_id):
            if job.state != "submitted":
                continue
            dependencies = [self.jobs[dep] for dep in job.dependencies]
            if any(dep.state in {"failed", "cancelled"} for dep in dependencies):
                job.state, job.failure_reason = "failed", "dependency_terminal_failure"
                self._event("reconcile-" + job.job_id, "failed", job.job_id, reason=job.failure_reason)
            elif all(dep.state == "succeeded" for dep in dependencies):
                job.state, job.queued_at = "queued", self.now
                self._event("release-" + job.job_id, "ready", job.job_id)

    def _available_profile(self, job: JobSpec) -> list[AgentSlot]:
        requested = set(job.required_capabilities)
        allowed = set(job.eligible_agents) or set(self.agents)
        profiles = []
        for agent_id in sorted(allowed):
            profile = self.agents.get(agent_id)
            if profile is None or not requested <= set(profile.capabilities):
                continue
            if self.available_agents[agent_id] < 1 or self._running_agent(agent_id) >= self.agent_quotas.get(agent_id, profile.max_concurrency):
                continue
            if not job.resources.fits(profile.capacity):
                continue
            profiles.append(profile)
        return profiles

    def _score(self, job: JobSpec) -> tuple[int, int, int, int, int, str]:
        queued_at = job.queued_at if job.queued_at is not None else job.submitted_at
        age = max(0, self.now - queued_at)
        effective = job.priority + age // self.aging_quantum
        tenant_service = sum(value for (tenant, _project), value in self.service.items() if tenant == job.tenant)
        project_service = self.service.get((job.tenant, job.project), 0)
        # Maximize the score.  Aging eventually dominates any finite priority
        # difference; virtual service breaks ties without starving tenants.
        return effective, -tenant_service, -project_service, -queued_at, -job.attempts, job.job_id

    def dispatch(self, operation_id: str, *, now: int, agent_id: str | None = None) -> DispatchLease | None:
        self.advance(now)
        request = {"action": "dispatch", "now": now, "agent_id": agent_id}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        self._ready()
        if self._running_count() >= self.max_concurrency:
            return self._remember(operation_id, request, None)
        candidates = []
        for job in self.jobs.values():
            if job.state != "queued" or (job.retry_at is not None and now < job.retry_at):
                continue
            if job.deadline is not None and now > job.deadline:
                job.state, job.failure_reason = "failed", "deadline_exceeded"
                self._event("deadline-" + job.job_id, "failed", job.job_id, reason=job.failure_reason)
                continue
            profiles = self._available_profile(job)
            if agent_id is not None:
                profiles = [profile for profile in profiles if profile.agent_id == agent_id]
            if profiles:
                candidates.append((job, profiles))
        if not candidates:
            return self._remember(operation_id, request, None)
        job, profiles = max(candidates, key=lambda pair: self._score(pair[0]))
        profile = min(profiles, key=lambda item: (self._running_agent(item.agent_id), self.agent_service.get(item.agent_id, 0), item.agent_id))
        self.fence += 1
        suffix = f"{job.job_id.removeprefix('JOB-')}-{self.fence}"
        lease = DispatchLease(
            job_id=job.job_id,
            lease_id=f"LSE-{suffix}",
            agent_id=profile.agent_id,
            fence=self.fence,
            expires_at=self.now + self.lease_seconds,
            coordinator_revision=self.authority_revision,
            profile_digest=profile.profile_digest,
            session_id=f"SES-{suffix}",
            worktree_key=f"{job.project}-{job.job_id.removeprefix('JOB-').lower()}",
            resources=job.resources,
        )
        job.state, job.attempts, job.lease = "running", job.attempts + 1, lease
        job.retry_at = None
        self.available = self.available.subtract(job.resources)
        self.available_agents[profile.agent_id] -= 1
        key = (job.tenant, job.project)
        self.service[key] = self.service.get(key, 0) + max(1, job.resources.cpu)
        self.agent_service[profile.agent_id] = self.agent_service.get(profile.agent_id, 0) + 1
        self._event(operation_id, "dispatched", job.job_id, agent_id=profile.agent_id, lease_id=lease.lease_id, fence=lease.fence)
        return self._remember(operation_id, request, lease)

    def _owned(self, job_id: str, lease: DispatchLease, now: int) -> JobSpec:
        job = self.jobs.get(job_id)
        if job is None or job.state not in {"running", "cancelling"} or job.lease != lease or now >= lease.expires_at:
            raise SchedulingError("stale_or_expired_lease")
        self.now = max(self.now, now)
        return job

    def complete(self, operation_id: str, *, job_id: str, lease: DispatchLease, now: int) -> str:
        request = {"action": "complete", "job_id": job_id, "lease": lease, "now": now}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        job = self._owned(job_id, lease, now)
        self._release(job)
        job.state = "succeeded"
        self._event(operation_id, "succeeded", job_id)
        return self._remember(operation_id, request, job.state)

    def fail(self, operation_id: str, *, job_id: str, lease: DispatchLease, reason: str, now: int) -> str:
        request = {"action": "fail", "job_id": job_id, "lease": lease, "reason": reason, "now": now}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        job = self._owned(job_id, lease, now)
        self._release(job)
        job.failure_reason = reason
        if reason in job.retryable and job.retries_used < job.retry_budget and job.attempts < job.max_attempts:
            job.retries_used += 1
            job.state, job.retry_at, job.queued_at = "queued", now + job.retry_backoff * (2 ** (job.retries_used - 1)), now
            self._event(operation_id, "retry_queued", job_id, retry_at=job.retry_at, retry=job.retries_used)
        else:
            job.state = "failed"
            self._event(operation_id, "failed", job_id, reason=reason)
        return self._remember(operation_id, request, job.state)

    def request_cancel(self, operation_id: str, *, job_id: str, now: int) -> str:
        request = {"action": "cancel", "job_id": job_id, "now": now}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        self.now = max(self.now, now)
        job = self.jobs.get(job_id)
        if job is None or job.state in TERMINAL:
            raise SchedulingError("unknown_or_terminal_job")
        job.cancel_requested = True
        if job.state in {"submitted", "queued"}:
            job.state = "cancelled"
            self._event(operation_id, "cancelled", job_id)
        else:
            job.state = "cancelling"
            self._event(operation_id, "cancellation_priority", job_id)
        return self._remember(operation_id, request, job.state)

    def acknowledge_cancel(self, operation_id: str, *, job_id: str, lease: DispatchLease, now: int) -> str:
        request = {"action": "ack_cancel", "job_id": job_id, "lease": lease, "now": now}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        job = self._owned(job_id, lease, now)
        if job.state != "cancelling" or not job.cancel_requested:
            raise SchedulingError("cancellation_not_requested")
        self._release(job)
        job.state = "cancelled"
        self._event(operation_id, "cancelled", job_id)
        return self._remember(operation_id, request, job.state)

    def advance(self, now: int) -> None:
        if isinstance(now, bool) or not isinstance(now, int) or now < self.now:
            raise SchedulingError("non_monotonic_virtual_time")
        self.now = now
        for job in list(self.jobs.values()):
            if job.state in {"running", "cancelling"} and job.lease is not None and now >= job.lease.expires_at:
                self._release(job)
                job.failure_reason = "lease_expired"
                if job.retries_used < job.retry_budget and job.attempts < job.max_attempts and not job.cancel_requested:
                    job.retries_used += 1
                    job.state, job.retry_at, job.queued_at = "queued", now + job.retry_backoff * (2 ** (job.retries_used - 1)), now
                    self._event("expire-" + job.job_id, "retry_queued", job.job_id, retry_at=job.retry_at)
                else:
                    job.state = "cancelled" if job.cancel_requested else "failed"
                    self._event("expire-" + job.job_id, job.state, job.job_id, reason=job.failure_reason)

    def heartbeat(self, operation_id: str, *, job_id: str, lease: DispatchLease, now: int) -> DispatchLease:
        request = {"action": "heartbeat", "job_id": job_id, "lease": lease, "now": now}
        replay, result = self._replay(operation_id, request)
        if replay:
            return result
        job = self._owned(job_id, lease, now)
        if job.state == "cancelling":
            raise SchedulingError("cancellation_in_progress")
        refreshed = DispatchLease(**{**asdict(lease), "expires_at": now + self.lease_seconds})
        job.lease = refreshed
        self._event(operation_id, "heartbeat", job_id, lease_id=lease.lease_id, expires_at=refreshed.expires_at)
        return self._remember(operation_id, request, refreshed)

    def _release(self, job: JobSpec) -> None:
        lease = job.lease
        if lease is None:
            return
        self.available = self.available.add(lease.resources)
        self.available_agents[lease.agent_id] += 1
        job.lease = None

    def snapshot(self) -> dict[str, Any]:
        jobs = {}
        for job_id, job in sorted(self.jobs.items()):
            value = asdict(job)
            value["resources"] = job.resources.as_dict()
            value["dependencies"] = list(job.dependencies)
            value["required_capabilities"] = sorted(job.required_capabilities)
            value["eligible_agents"] = sorted(job.eligible_agents)
            value["retryable"] = sorted(job.retryable)
            jobs[job_id] = value
        return {
            "protocol": PROTOCOL,
            "task": TASK,
            "jobs": jobs,
            "available": self.available.as_dict(),
            "available_agents": dict(sorted(self.available_agents.items())),
            "events": list(self.events),
            "fence": self.fence,
            "now": self.now,
            "execute": False,
            "network": "disabled",
            "provider": "not_performed",
            "llm": "not_performed",
        }


__all__ = [
    "PROTOCOL",
    "TASK",
    "AgentSlot",
    "DispatchLease",
    "FairScheduler",
    "JobSpec",
    "Resources",
    "SchedulingError",
    "canonical",
    "digest",
]

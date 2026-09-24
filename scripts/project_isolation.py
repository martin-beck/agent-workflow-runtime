#!/usr/bin/env python3
"""Offline multi-project isolation and artifact-routing boundary for AR-0087.

The registry is an AWR projection, not a replacement for Coordinator. A
DispatchLease is supplied by the AR-0086 scheduler and is only checked here;
lease ownership, task identity, revisions, and terminal commits remain
Coordinator-owned. The local store uses opaque worktree tokens and never
touches a host checkout.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from scripts.fair_scheduler import DispatchLease, Resources


class IsolationError(ValueError):
    """A fail-closed routing, provenance, or recovery violation."""


class UnknownCleanupOutcome(IsolationError):
    """Cleanup committed a pending state but its response was lost."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


_PROJECT = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_TASK = re.compile(r"^(?:AR-[0-9]{4}|JOB-[A-Z0-9-]{1,63})$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_WORKTREE = re.compile(r"^(?:WT-[A-Z0-9-]{3,127}|[a-z][a-z0-9._-]{2,127})$")
_ARTIFACT = re.compile(r"^ART-[A-Z0-9-]{1,63}$")
_WORKER = re.compile(r"^(?:WRK-[A-Z0-9-]{1,63}|[a-z][a-z0-9-]{1,63})$")
_LEASE = re.compile(r"^LSE-[A-Z0-9-]{1,63}$")
_SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
_OPERATION = re.compile(r"^OP-[A-Z0-9-]{1,127}$")


def _match(pattern: re.Pattern[str], value: Any, name: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise IsolationError("invalid_" + name)
    return value


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise IsolationError("invalid_" + name)
    return value


@dataclass(frozen=True)
class RoutingContext:
    """One exact scheduler claim consumed by the routing boundary."""

    task_id: str
    task_revision: int
    tenant: str
    project_key: str
    project_revision: str
    worktree_key: str
    worker_id: str
    lease_id: str
    fence: int
    session_id: str
    coordinator_revision: int

    @classmethod
    def from_dispatch(
        cls,
        lease: DispatchLease,
        *,
        task_revision: int,
        tenant: str,
        project_key: str,
        project_revision: str,
    ) -> RoutingContext:
        context = cls(
            task_id=lease.job_id,
            task_revision=task_revision,
            tenant=tenant,
            project_key=project_key,
            project_revision=project_revision,
            worktree_key=lease.worktree_key,
            worker_id=lease.agent_id,
            lease_id=lease.lease_id,
            fence=lease.fence,
            session_id=lease.session_id,
            coordinator_revision=lease.coordinator_revision,
        )
        context.validate(lease)
        return context

    def validate(self, lease: DispatchLease | None = None) -> None:
        _match(_TASK, self.task_id, "task_id")
        _positive(self.task_revision, "task_revision")
        _match(_PROJECT, self.tenant, "tenant")
        _match(_PROJECT, self.project_key, "project_key")
        if _REVISION.fullmatch(self.project_revision) is None:
            raise IsolationError("invalid_project_revision")
        _match(_WORKTREE, self.worktree_key, "worktree_key")
        _match(_WORKER, self.worker_id, "worker_id")
        _match(_LEASE, self.lease_id, "lease_id")
        _match(_SESSION, self.session_id, "session_id")
        _positive(self.fence, "fence")
        _positive(self.coordinator_revision, "coordinator_revision")
        if self.coordinator_revision != self.task_revision:
            raise IsolationError("stale_coordinator_revision")
        if lease is not None:
            if lease.job_id != self.task_id:
                raise IsolationError("crossed_task_lease")
            if lease.coordinator_revision != self.task_revision:
                raise IsolationError("stale_dispatch_lease")
            expected = {
                "worktree_key": lease.worktree_key,
                "worker_id": lease.agent_id,
                "lease_id": lease.lease_id,
                "fence": lease.fence,
                "session_id": lease.session_id,
            }
            actual = {key: getattr(self, key) for key in expected}
            if actual != expected:
                raise IsolationError("dispatch_binding_mismatch")

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "tenant": self.tenant,
            "project_key": self.project_key,
            "project_revision": self.project_revision,
            "worktree_key": self.worktree_key,
            "worker_id": self.worker_id,
            "lease_id": self.lease_id,
            "fence": self.fence,
            "session_id": self.session_id,
            "coordinator_revision": self.coordinator_revision,
        }


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    tenant: str
    project_key: str
    project_revision: str
    task_id: str
    task_revision: int
    worktree_key: str
    worker_id: str
    lease_id: str
    fence: int
    session_id: str
    content_digest: str
    provenance_digest: str
    sequence: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "tenant": self.tenant,
            "project_key": self.project_key,
            "project_revision": self.project_revision,
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "worktree_key": self.worktree_key,
            "worker_id": self.worker_id,
            "lease_id": self.lease_id,
            "fence": self.fence,
            "session_id": self.session_id,
            "content_digest": self.content_digest,
            "provenance_digest": self.provenance_digest,
            "sequence": self.sequence,
        }


@dataclass
class _Project:
    tenant: str
    project_revision: str


@dataclass
class _Worktree:
    context: RoutingContext
    binding_digest: str
    state: str = "active"
    cleanup_fence: int | None = None


class ProjectIsolationRegistry:
    """Deterministic in-memory registry and artifact router.

    It has no authority over Coordinator state and does not create a physical
    checkout. LocalProjectFake supplies deterministic content and interruption
    faults for tests and contract qualification.
    """

    def __init__(self) -> None:
        self.projects: dict[str, _Project] = {}
        self.worktrees: dict[str, _Worktree] = {}
        self.artifacts: dict[tuple[str, str, str], ArtifactRecord] = {}
        self._payloads: dict[tuple[str, str, str], Any] = {}
        self.dependencies: set[tuple[str, str, str, str, str, str]] = set()
        self.operations: dict[str, tuple[str, Any]] = {}
        self.events: list[dict[str, Any]] = []

    def register_project(
        self, project_key: str, *, tenant: str, project_revision: str
    ) -> dict[str, str]:
        _match(_PROJECT, project_key, "project_key")
        _match(_PROJECT, tenant, "tenant")
        if _REVISION.fullmatch(project_revision) is None:
            raise IsolationError("invalid_project_revision")
        old = self.projects.get(project_key)
        if old is not None:
            if old.tenant != tenant or old.project_revision != project_revision:
                raise IsolationError("project_registration_conflict")
            return {
                "project_key": project_key,
                "tenant": tenant,
                "project_revision": project_revision,
            }
        self.projects[project_key] = _Project(tenant, project_revision)
        self._event("project_registered", project_key=project_key, tenant=tenant)
        return {
            "project_key": project_key,
            "tenant": tenant,
            "project_revision": project_revision,
        }

    def allocate_worktree(
        self, context: RoutingContext, lease: DispatchLease | None = None
    ) -> dict[str, Any]:
        context.validate(lease)
        project = self.projects.get(context.project_key)
        if (
            project is None
            or project.tenant != context.tenant
            or project.project_revision != context.project_revision
        ):
            raise IsolationError("project_binding_mismatch")
        existing = self.worktrees.get(context.worktree_key)
        binding_digest = digest(context.as_dict())
        if existing is not None:
            if existing.binding_digest != binding_digest:
                raise IsolationError("worktree_collision")
            return self._worktree_result(existing)
        self.worktrees[context.worktree_key] = _Worktree(context, binding_digest)
        self._event(
            "worktree_allocated",
            project_key=context.project_key,
            worktree_key=context.worktree_key,
            fence=context.fence,
        )
        return self._worktree_result(self.worktrees[context.worktree_key])

    def allow_dependency(
        self,
        consumer_project: str,
        producer_project: str,
        artifact_id: str,
        *,
        source_worktree_key: str,
        content_digest: str,
        provenance_digest: str,
    ) -> None:
        _match(_PROJECT, consumer_project, "consumer_project")
        _match(_PROJECT, producer_project, "producer_project")
        _match(_ARTIFACT, artifact_id, "artifact_id")
        _match(_WORKTREE, source_worktree_key, "source_worktree_key")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", content_digest or ""):
            raise IsolationError("invalid_content_digest")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", provenance_digest or ""):
            raise IsolationError("invalid_provenance_digest")
        consumer = self.projects.get(consumer_project)
        producer = self.projects.get(producer_project)
        if consumer is None or producer is None:
            raise IsolationError("unknown_project")
        if consumer.tenant != producer.tenant:
            raise IsolationError("cross_tenant_dependency")
        key = (producer_project, source_worktree_key, artifact_id)
        record = self.artifacts.get(key)
        if record is None:
            raise IsolationError("artifact_not_routable")
        self._verify_artifact(key, record)
        if (
            record.content_digest != content_digest
            or record.provenance_digest != provenance_digest
        ):
            raise IsolationError("dependency_digest_mismatch")
        self.dependencies.add(
            (
                consumer_project,
                producer_project,
                artifact_id,
                source_worktree_key,
                content_digest,
                provenance_digest,
            )
        )

    def put_artifact(
        self, context: RoutingContext, artifact_id: str, payload: Any
    ) -> ArtifactRecord:
        self._require_active(context)
        _match(_ARTIFACT, artifact_id, "artifact_id")
        key = (context.project_key, context.worktree_key, artifact_id)
        content_digest = digest(payload)
        provenance = {
            "artifact_id": artifact_id,
            "context": context.as_dict(),
            "content_digest": content_digest,
        }
        provenance_digest = digest(provenance)
        prior = self.artifacts.get(key)
        if prior is not None:
            if (
                prior.content_digest != content_digest
                or prior.provenance_digest != provenance_digest
            ):
                raise IsolationError("artifact_rewrite_or_digest_mismatch")
            return prior
        record = ArtifactRecord(
            artifact_id=artifact_id,
            tenant=context.tenant,
            project_key=context.project_key,
            project_revision=context.project_revision,
            task_id=context.task_id,
            task_revision=context.task_revision,
            worktree_key=context.worktree_key,
            worker_id=context.worker_id,
            lease_id=context.lease_id,
            fence=context.fence,
            session_id=context.session_id,
            content_digest=content_digest,
            provenance_digest=provenance_digest,
            sequence=len(self.artifacts) + 1,
        )
        self.artifacts[key] = record
        self._payloads[key] = deepcopy(payload)
        self._event(
            "artifact_published",
            project_key=context.project_key,
            worktree_key=context.worktree_key,
            artifact_id=artifact_id,
            content_digest=content_digest,
        )
        return record

    def read_artifact(
        self, context: RoutingContext, artifact_id: str
    ) -> tuple[ArtifactRecord, Any]:
        self._require_active(context)
        _match(_ARTIFACT, artifact_id, "artifact_id")
        key = (context.project_key, context.worktree_key, artifact_id)
        record = self.artifacts.get(key)
        if record is None:
            raise IsolationError("artifact_not_routable")
        self._verify_artifact(key, record)
        return record, deepcopy(self._payloads[key])

    def read_dependency(
        self, context: RoutingContext, producer_project: str, artifact_id: str
    ) -> tuple[ArtifactRecord, Any]:
        self._require_active(context)
        _match(_PROJECT, producer_project, "producer_project")
        _match(_ARTIFACT, artifact_id, "artifact_id")
        producer = self.projects.get(producer_project)
        if producer is None or producer.tenant != context.tenant:
            raise IsolationError("cross_tenant_dependency")
        grants = [
            grant
            for grant in self.dependencies
            if grant[0] == context.project_key
            and grant[1] == producer_project
            and grant[2] == artifact_id
        ]
        if len(grants) != 1:
            if not grants:
                raise IsolationError("dependency_not_granted")
            raise IsolationError("artifact_not_routable")
        (
            _consumer,
            _producer,
            _artifact,
            source_worktree,
            content_digest,
            provenance_digest,
        ) = grants[0]
        record = self.artifacts.get((producer_project, source_worktree, artifact_id))
        if record is None:
            raise IsolationError("artifact_not_routable")
        if record.tenant != context.tenant or record.project_key != producer_project:
            raise IsolationError("artifact_provenance_mismatch")
        if (
            record.content_digest != content_digest
            or record.provenance_digest != provenance_digest
        ):
            raise IsolationError("dependency_digest_mismatch")
        self._verify_artifact((producer_project, source_worktree, artifact_id), record)
        payload = self._payloads[(producer_project, record.worktree_key, artifact_id)]
        return record, deepcopy(payload)

    def cleanup_worktree(
        self, context: RoutingContext, operation_id: str, *, interrupted: bool = False
    ) -> dict[str, Any]:
        self._require_operation(operation_id)
        worktree = self._require_worktree(context)
        request = {
            "operation": "cleanup",
            "context": context.as_dict(),
            "interrupted": interrupted,
        }
        replay = self._replay(operation_id, request)
        if replay is not None:
            return replay
        if worktree.state == "cleaned":
            raise IsolationError("worktree_already_cleaned")
        worktree.state = "cleanup_pending" if interrupted else "cleaned"
        worktree.cleanup_fence = context.fence
        result = {
            "disposition": "pending" if interrupted else "cleaned",
            "worktree_key": context.worktree_key,
            "binding_digest": worktree.binding_digest,
        }
        self._remember(operation_id, request, result)
        self._event(
            "worktree_cleanup_pending" if interrupted else "worktree_cleaned",
            project_key=context.project_key,
            worktree_key=context.worktree_key,
            fence=context.fence,
        )
        if interrupted:
            raise UnknownCleanupOutcome("cleanup_response_lost")
        return result

    def recover_cleanup(
        self, context: RoutingContext, operation_id: str
    ) -> dict[str, Any]:
        self._require_operation(operation_id)
        worktree = self._require_worktree(context)
        request = {"operation": "recover_cleanup", "context": context.as_dict()}
        replay = self._replay(operation_id, request)
        if replay is not None:
            return replay
        if worktree.state != "cleanup_pending":
            raise IsolationError("cleanup_not_recoverable")
        if worktree.cleanup_fence is None or context.fence <= worktree.cleanup_fence:
            raise IsolationError("recovery_requires_new_fence")
        worktree.state = "cleaned"
        result = {
            "disposition": "recovered_cleaned",
            "worktree_key": context.worktree_key,
            "binding_digest": worktree.binding_digest,
        }
        self._remember(operation_id, request, result)
        self._event(
            "worktree_cleanup_recovered",
            project_key=context.project_key,
            worktree_key=context.worktree_key,
            fence=context.fence,
        )
        return result

    def snapshot(self) -> dict[str, Any]:
        return {
            "projects": {
                key: {
                    "tenant": value.tenant,
                    "project_revision": value.project_revision,
                }
                for key, value in sorted(self.projects.items())
            },
            "worktrees": {
                key: self._worktree_result(value)
                for key, value in sorted(self.worktrees.items())
            },
            "artifacts": [
                record.as_dict()
                for record in sorted(
                    self.artifacts.values(), key=lambda item: item.sequence
                )
            ],
            "dependencies": sorted(self.dependencies),
            "events": deepcopy(self.events),
        }

    def _require_active(self, context: RoutingContext) -> _Worktree:
        worktree = self._require_worktree(context)
        if worktree.state != "active":
            raise IsolationError("worktree_not_active")
        if worktree.context != context:
            raise IsolationError("stale_or_crossed_worktree_binding")
        return worktree

    def _require_worktree(self, context: RoutingContext) -> _Worktree:
        context.validate()
        worktree = self.worktrees.get(context.worktree_key)
        if worktree is None:
            raise IsolationError("unknown_worktree")
        if (
            worktree.context.project_key != context.project_key
            or worktree.context.tenant != context.tenant
            or worktree.context.project_revision != context.project_revision
            or worktree.context.task_id != context.task_id
            or worktree.context.task_revision != context.task_revision
        ):
            raise IsolationError("cross_project_or_revision")
        return worktree

    def _verify_artifact(
        self, key: tuple[str, str, str], record: ArtifactRecord
    ) -> None:
        payload = self._payloads.get(key)
        if payload is None:
            raise IsolationError("artifact_payload_missing")
        if digest(payload) != record.content_digest:
            raise IsolationError("artifact_content_digest_mismatch")
        provenance = {
            "artifact_id": record.artifact_id,
            "context": {
                "task_id": record.task_id,
                "task_revision": record.task_revision,
                "tenant": record.tenant,
                "project_key": record.project_key,
                "project_revision": record.project_revision,
                "worktree_key": record.worktree_key,
                "worker_id": record.worker_id,
                "lease_id": record.lease_id,
                "fence": record.fence,
                "session_id": record.session_id,
                "coordinator_revision": record.task_revision,
            },
            "content_digest": record.content_digest,
        }
        if digest(provenance) != record.provenance_digest:
            raise IsolationError("artifact_provenance_digest_mismatch")

    def _worktree_result(self, worktree: _Worktree) -> dict[str, Any]:
        return {
            "worktree_key": worktree.context.worktree_key,
            "path_token": "wt://"
            + worktree.context.project_key
            + "/"
            + worktree.context.worktree_key,
            "binding_digest": worktree.binding_digest,
            "state": worktree.state,
            "fence": worktree.context.fence,
        }

    def _event(self, kind: str, **details: Any) -> None:
        event = {"sequence": len(self.events) + 1, "kind": kind, **details}
        event["digest"] = digest(event)
        self.events.append(event)

    def _require_operation(self, operation_id: str) -> None:
        _match(_OPERATION, operation_id, "operation_id")

    def _replay(self, operation_id: str, request: Mapping[str, Any]) -> Any:
        old = self.operations.get(operation_id)
        if old is None:
            return None
        if old[0] != digest(request):
            raise IsolationError("idempotency_conflict")
        return deepcopy(old[1])

    def _remember(
        self, operation_id: str, request: Mapping[str, Any], result: Any
    ) -> None:
        self.operations[operation_id] = (digest(request), deepcopy(result))


class LocalProjectFake:
    """Deterministic content fake without Git, network, or LLM."""

    def __init__(self, registry: ProjectIsolationRegistry):
        self.registry = registry

    def publish_json(
        self, context: RoutingContext, artifact_id: str, value: Mapping[str, Any]
    ) -> ArtifactRecord:
        if not isinstance(value, Mapping):
            raise IsolationError("fake_payload_must_be_mapping")
        return self.registry.put_artifact(context, artifact_id, dict(value))


def make_dispatch_lease(
    *, job_id: str, project: str, task_revision: int, agent_id: str, fence: int = 1
) -> DispatchLease:
    """Build a deterministic fixture lease; production callers use AR-0086."""
    return DispatchLease(
        job_id=job_id,
        lease_id=f"LSE-{job_id.removeprefix('JOB-')}-{fence}",
        agent_id=agent_id,
        fence=fence,
        expires_at=100,
        coordinator_revision=task_revision,
        profile_digest=digest({"agent": agent_id}),
        session_id=f"SES-{job_id.removeprefix('JOB-')}-{fence}",
        worktree_key=f"WT-{project.upper()}-{job_id.removeprefix('JOB-')}-{fence}",
        resources=Resources(),
    )

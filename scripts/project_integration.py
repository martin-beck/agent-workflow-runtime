#!/usr/bin/env python3
"""Provider-neutral Agent Workflow project integration contract (AR-0089).

This module is a deliberately narrow runtime boundary.  It consumes an
already-issued AR-0086 dispatch lease and an AR-0087 routing context, and it
accepts an injected authority port for AWQ evidence handoff.  It does not
create leases, approve evidence, interpret project policy, or run a provider.
The local fake at the bottom is a deterministic record/replay test double.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Protocol

from scripts.fair_scheduler import DispatchLease
from scripts.project_isolation import (
    ArtifactRecord,
    IsolationError,
    ProjectIsolationRegistry,
    RoutingContext,
)

PROTOCOL = {"id": "awr-project-integration", "version": "1.0.0"}
TASK = {"id": "AR-0089", "revision": 3}

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PROJECT_REVISION = re.compile(r"^[0-9a-f]{40}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
TASK_ID = re.compile(r"^(?:AR-[0-9]{4}|JOB-[A-Z0-9-]{1,63})$")
OPAQUE = re.compile(r"^(?:CAP|EVD|OP|REQ|RUN|SES|ART|TERM)-[A-Z0-9-]{1,63}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
TERMINAL = {"succeeded", "failed", "blocked", "cancelled"}
RUN_STATES = {"registered", "admitted", "executing", "evidence_pending", "terminal"}


class IntegrationError(ValueError):
    """A fail-closed contract, binding, evidence, or reconciliation error."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _match(pattern: re.Pattern[str], value: Any, name: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise IntegrationError("invalid_" + name)
    return value


def _digest(value: Any, name: str) -> str:
    result = _match(DIGEST, value, name)
    return result


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise IntegrationError("invalid_" + name)
    return value


@dataclass(frozen=True)
class ProjectRegistration:
    """Generic identity/capability declaration; no application policy."""

    project_key: str
    tenant: str
    project_revision: str
    capabilities: frozenset[str] = frozenset()
    contract_version: str = "1.0.0"

    def validate(self) -> ProjectRegistration:
        _match(PROJECT, self.project_key, "project_key")
        _match(PROJECT, self.tenant, "tenant")
        _match(PROJECT_REVISION, self.project_revision, "project_revision")
        if self.contract_version != "1.0.0":
            raise IntegrationError("unsupported_contract_version")
        if not isinstance(self.capabilities, frozenset):
            raise IntegrationError("capabilities_must_be_frozen")
        for capability in self.capabilities:
            _match(CAPABILITY, capability, "capability")
        return self

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "project_key": self.project_key,
            "tenant": self.tenant,
            "project_revision": self.project_revision,
            "capabilities": sorted(self.capabilities),
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True)
class TaskIntake:
    """An immutable generic task envelope accepted from a consuming project."""

    task_id: str
    task_revision: int
    input_digest: str
    required_capabilities: frozenset[str] = frozenset()
    policy_reference: str | None = None

    def validate(self) -> TaskIntake:
        _match(TASK_ID, self.task_id, "task_id")
        _positive(self.task_revision, "task_revision")
        _digest(self.input_digest, "input_digest")
        if not isinstance(self.required_capabilities, frozenset):
            raise IntegrationError("required_capabilities_must_be_frozen")
        for capability in self.required_capabilities:
            _match(CAPABILITY, capability, "required_capability")
        if self.policy_reference is not None:
            _digest(self.policy_reference, "policy_reference")
        return self

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        result: dict[str, Any] = {
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "input_digest": self.input_digest,
            "required_capabilities": sorted(self.required_capabilities),
        }
        if self.policy_reference is not None:
            result["policy_reference"] = self.policy_reference
        return result


@dataclass(frozen=True)
class SessionBoundary:
    """The minimum session metadata needed to cross AR-0085 safely."""

    session_id: str
    session_digest: str
    adapter_capabilities: frozenset[str] = frozenset()

    def validate(self) -> SessionBoundary:
        _match(re.compile(r"^SES-[A-Z0-9-]{1,63}$"), self.session_id, "session_id")
        _digest(self.session_digest, "session_digest")
        if not isinstance(self.adapter_capabilities, frozenset):
            raise IntegrationError("adapter_capabilities_must_be_frozen")
        for capability in self.adapter_capabilities:
            _match(CAPABILITY, capability, "adapter_capability")
        return self

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "session_id": self.session_id,
            "session_digest": self.session_digest,
            "adapter_capabilities": sorted(self.adapter_capabilities),
        }


@dataclass(frozen=True)
class EvidenceEnvelope:
    """A content-addressed AWQ handoff; evidence meaning stays with AWQ."""

    evidence_id: str
    task_id: str
    task_revision: int
    artifact_id: str
    artifact_digest: str
    evidence_digest: str
    binding_digest: str

    def validate(self) -> EvidenceEnvelope:
        _match(OPAQUE, self.evidence_id, "evidence_id")
        if not self.evidence_id.startswith("EVD-"):
            raise IntegrationError("invalid_evidence_id")
        _match(TASK_ID, self.task_id, "task_id")
        _positive(self.task_revision, "task_revision")
        _match(OPAQUE, self.artifact_id, "artifact_id")
        if not self.artifact_id.startswith("ART-"):
            raise IntegrationError("invalid_artifact_id")
        _digest(self.artifact_digest, "artifact_digest")
        _digest(self.evidence_digest, "evidence_digest")
        _digest(self.binding_digest, "binding_digest")
        return self

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "evidence_id": self.evidence_id,
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "artifact_id": self.artifact_id,
            "artifact_digest": self.artifact_digest,
            "evidence_digest": self.evidence_digest,
            "binding_digest": self.binding_digest,
        }


class EvidenceAuthority(Protocol):
    """Structural AWQ port; an AuthorityBridge is supplied by the caller."""

    def request(self, authority: str, request_id: str, kind: str, payload: Any, *, operation_id: str, max_attempts: int = 3, change_kind: str = "none") -> dict[str, Any]: ...

    def observe(self, operation_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class TerminalObservation:
    status: str
    task_id: str
    task_revision: int
    terminal_digest: str
    evidence_digest: str | None
    source: str

    def validate(self) -> TerminalObservation:
        if self.status not in TERMINAL:
            raise IntegrationError("invalid_terminal_status")
        _match(TASK_ID, self.task_id, "task_id")
        _positive(self.task_revision, "task_revision")
        _digest(self.terminal_digest, "terminal_digest")
        if self.evidence_digest is not None:
            _digest(self.evidence_digest, "evidence_digest")
        if self.source not in {"project", "runtime", "replay"}:
            raise IntegrationError("invalid_terminal_source")
        return self

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "status": self.status,
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "terminal_digest": self.terminal_digest,
            "evidence_digest": self.evidence_digest,
            "source": self.source,
        }


@dataclass
class _Run:
    registration: ProjectRegistration
    intake: TaskIntake
    context: RoutingContext
    session: SessionBoundary
    state: str = "registered"
    artifacts: dict[str, ArtifactRecord] = field(default_factory=dict)
    evidence: EvidenceEnvelope | None = None
    evidence_status: str | None = None
    authority_operation: str | None = None
    terminal: TerminalObservation | None = None


class ProjectIntegrationRuntime:
    """Generic integration facade over isolation, session, and AWQ ports."""

    def __init__(
        self,
        registry: ProjectIsolationRegistry,
        authority: EvidenceAuthority,
        *,
        protocol_revision: int = 3,
    ) -> None:
        self.registry = registry
        self.authority = authority
        self.protocol_revision = protocol_revision
        self.projects: dict[str, ProjectRegistration] = {}
        self.runs: dict[str, _Run] = {}
        self.operations: dict[str, tuple[str, Any]] = {}
        self.events: list[dict[str, Any]] = []

    def register(self, registration: ProjectRegistration) -> dict[str, Any]:
        registration.validate()
        prior = self.projects.get(registration.project_key)
        if prior is not None and prior != registration:
            raise IntegrationError("registration_conflict")
        self.registry.register_project(
            registration.project_key,
            tenant=registration.tenant,
            project_revision=registration.project_revision,
        )
        self.projects[registration.project_key] = registration
        self._event("project_registered", registration=registration.as_dict())
        return registration.as_dict()

    def intake(
        self,
        registration: ProjectRegistration,
        intake: TaskIntake,
        context: RoutingContext,
        session: SessionBoundary,
        *,
        lease: DispatchLease | None = None,
    ) -> str:
        registration.validate()
        intake.validate()
        session.validate()
        try:
            context.validate(lease)
        except IsolationError as exc:
            raise IntegrationError("binding_mismatch") from exc
        if context.project_key != registration.project_key or context.tenant != registration.tenant:
            raise IntegrationError("cross_project_binding")
        if self.projects.get(registration.project_key) != registration:
            raise IntegrationError("project_not_registered")
        if context.project_revision != registration.project_revision:
            raise IntegrationError("stale_project_revision")
        if context.task_id != intake.task_id or context.task_revision != intake.task_revision:
            raise IntegrationError("stale_task_revision")
        if context.session_id != session.session_id:
            raise IntegrationError("session_binding_mismatch")
        if not intake.required_capabilities <= registration.capabilities:
            raise IntegrationError("project_capability_mismatch")
        if not intake.required_capabilities <= session.adapter_capabilities:
            raise IntegrationError("session_capability_mismatch")
        run_key = self._run_key(context)
        if run_key in self.runs:
            prior = self.runs[run_key]
            if (prior.registration, prior.intake, prior.context, prior.session) != (registration, intake, context, session):
                raise IntegrationError("changed_intake_replay")
            return run_key
        self.registry.allocate_worktree(context, lease)
        self.runs[run_key] = _Run(registration, intake, context, session, state="admitted")
        self._event("task_admitted", run=run_key, project_key=registration.project_key)
        return run_key

    def begin(self, run_key: str, operation_id: str) -> dict[str, Any]:
        run = self._run(run_key)
        _match(OPAQUE, operation_id, "operation_id")
        if not operation_id.startswith("OP-"):
            raise IntegrationError("invalid_operation_id")
        if run.state != "admitted":
            raise IntegrationError("invalid_run_state")
        replay = self._replay(operation_id, {"operation": "begin", "run": run_key})
        if replay is not None:
            return replay
        run.state = "executing"
        result = {"run": run_key, "state": run.state, "binding_digest": self._binding_digest(run)}
        self._remember(operation_id, {"operation": "begin", "run": run_key}, result)
        self._event("task_started", run=run_key)
        return deepcopy(result)

    def publish_artifact(self, run_key: str, artifact_id: str, payload: Any) -> ArtifactRecord:
        run = self._run(run_key)
        if run.state not in {"executing", "evidence_pending"}:
            raise IntegrationError("artifact_after_terminal")
        record = self.registry.put_artifact(run.context, artifact_id, payload)
        run.artifacts[artifact_id] = record
        self._event("artifact_exchanged", run=run_key, artifact_id=artifact_id, digest=record.content_digest)
        return record

    def handoff_evidence(
        self,
        run_key: str,
        artifact_id: str,
        evidence_id: str,
        evidence_payload: Any,
        *,
        operation_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        run = self._run(run_key)
        if run.state not in {"executing", "evidence_pending"}:
            raise IntegrationError("evidence_requires_executing")
        artifact = run.artifacts.get(artifact_id)
        if artifact is None:
            raise IntegrationError("evidence_artifact_missing")
        _match(OPAQUE, evidence_id, "evidence_id")
        if not evidence_id.startswith("EVD-"):
            raise IntegrationError("invalid_evidence_id")
        envelope = EvidenceEnvelope(
            evidence_id=evidence_id,
            task_id=run.intake.task_id,
            task_revision=run.intake.task_revision,
            artifact_id=artifact_id,
            artifact_digest=artifact.content_digest,
            evidence_digest=digest(evidence_payload),
            binding_digest=self._binding_digest(run),
        )
        envelope.validate()
        if run.evidence is not None:
            if run.evidence != envelope:
                raise IntegrationError("contradictory_evidence")
            return {"status": "replayed", "evidence": envelope.as_dict()}
        result = self.authority.request(
            "awq",
            request_id,
            "evidence",
            envelope.as_dict(),
            operation_id=operation_id,
            max_attempts=3,
        )
        if result.get("binding_digest") != self._authority_binding_digest(run):
            raise IntegrationError("crossed_authority_result")
        status = result.get("status")
        if status not in {"accepted", "pending", "rejected", "timeout", "unknown"}:
            raise IntegrationError("ambiguous_authority_result")
        run.evidence = envelope
        run.evidence_status = status
        run.authority_operation = operation_id
        run.state = "evidence_pending"
        self._event("evidence_handoff", run=run_key, evidence_id=evidence_id, status=status)
        return {"status": status, "evidence": envelope.as_dict(), "authority": deepcopy(result)}

    def observe_evidence(self, run_key: str) -> dict[str, Any]:
        run = self._run(run_key)
        if run.authority_operation is None or run.evidence is None:
            raise IntegrationError("evidence_not_handed_off")
        result = self.authority.observe(run.authority_operation)
        if result.get("binding_digest") != self._authority_binding_digest(run):
            raise IntegrationError("crossed_authority_result")
        if result.get("status") not in {"accepted", "pending", "rejected", "timeout", "unknown"}:
            raise IntegrationError("ambiguous_authority_result")
        if result.get("status") == "accepted":
            run.evidence_status = "accepted"
            run.state = "executing"
        return deepcopy(result)

    def reconcile_terminal(
        self,
        run_key: str,
        status: str,
        *,
        terminal_payload: Any,
        evidence_digest: str | None = None,
        source: str = "project",
        operation_id: str,
    ) -> dict[str, Any]:
        run = self._run(run_key)
        if status not in TERMINAL:
            raise IntegrationError("invalid_terminal_status")
        _match(OPAQUE, operation_id, "operation_id")
        if not operation_id.startswith("TERM-"):
            raise IntegrationError("invalid_terminal_operation")
        if run.state not in {"executing", "evidence_pending", "terminal"}:
            raise IntegrationError("invalid_run_state")
        if status == "succeeded" and (run.evidence is None or run.evidence_status != "accepted" or evidence_digest != run.evidence.evidence_digest):
            raise IntegrationError("missing_or_mismatched_evidence")
        terminal = TerminalObservation(
            status=status,
            task_id=run.intake.task_id,
            task_revision=run.intake.task_revision,
            terminal_digest=digest(terminal_payload),
            evidence_digest=evidence_digest,
            source=source,
        )
        terminal.validate()
        if run.terminal is not None:
            if run.terminal != terminal:
                raise IntegrationError("contradictory_terminal")
            return {"status": "replayed", "terminal": terminal.as_dict()}
        replay = self._replay(operation_id, {"operation": "terminal", "run": run_key, "terminal": terminal.as_dict()})
        if replay is not None:
            return replay
        run.terminal = terminal
        run.state = "terminal"
        result = {"status": "reconciled", "terminal": terminal.as_dict(), "binding_digest": self._binding_digest(run)}
        self._remember(operation_id, {"operation": "terminal", "run": run_key, "terminal": terminal.as_dict()}, result)
        self._event("terminal_reconciled", run=run_key, status=status)
        return deepcopy(result)

    def snapshot(self) -> dict[str, Any]:
        return {
            "protocol": PROTOCOL,
            "projects": {key: value.as_dict() for key, value in sorted(self.projects.items())},
            "runs": {
                key: {
                    "project_key": value.registration.project_key,
                    "task_id": value.intake.task_id,
                    "task_revision": value.intake.task_revision,
                    "state": value.state,
                    "artifacts": sorted(value.artifacts),
                    "evidence": value.evidence.as_dict() if value.evidence else None,
                    "terminal": value.terminal.as_dict() if value.terminal else None,
                }
                for key, value in sorted(self.runs.items())
            },
            "events": deepcopy(self.events),
        }

    def _run(self, run_key: str) -> _Run:
        if run_key not in self.runs:
            raise IntegrationError("unknown_run")
        return self.runs[run_key]

    @staticmethod
    def _run_key(context: RoutingContext) -> str:
        return f"{context.project_key}:{context.task_id}:{context.task_revision}:{context.worktree_key}"

    @staticmethod
    def _binding_digest(run: _Run) -> str:
        return digest(
            {
                "task_id": run.intake.task_id,
                "task_revision": run.intake.task_revision,
                "project_key": run.registration.project_key,
                "project_revision": run.registration.project_revision,
                "tenant": run.registration.tenant,
                "worktree_key": run.context.worktree_key,
                "lease_id": run.context.lease_id,
                "fence": run.context.fence,
                "session_id": run.session.session_id,
            }
        )

    def _authority_binding_digest(self, run: _Run) -> str:
        # Authority bridges consume a binding digest.  The exact project/task
        # binding is intentionally opaque to the authority adapter.
        return self._binding_digest(run)

    def _event(self, kind: str, **details: Any) -> None:
        event = {"sequence": len(self.events) + 1, "kind": kind, **details}
        event["digest"] = digest(event)
        self.events.append(event)

    def _remember(self, operation_id: str, request: Any, result: Any) -> None:
        self.operations[operation_id] = (digest(request), deepcopy(result))

    def _replay(self, operation_id: str, request: Any) -> Any:
        old = self.operations.get(operation_id)
        if old is None:
            return None
        if old[0] != digest(request):
            raise IntegrationError("idempotency_conflict")
        return deepcopy(old[1])

class LocalAuthorityPort:
    """AWQ-shaped deterministic response port for offline contract tests."""

    def __init__(self, responses: list[str] | None = None, *, binding_digest: str | None = None):
        self.responses = list(responses or [])
        self.binding_digest = binding_digest
        self.completed: dict[str, dict[str, Any]] = {}
        self.request_log: dict[str, dict[str, Any]] = {}

    def request(self, authority: str, request_id: str, kind: str, payload: Any, *, operation_id: str, max_attempts: int = 3, change_kind: str = "none") -> dict[str, Any]:
        if authority != "awq" or kind != "evidence":
            raise IntegrationError("invalid_awq_port_request")
        _match(OPAQUE, request_id, "request_id")
        _match(OPAQUE, operation_id, "operation_id")
        fingerprint = digest({"request_id": request_id, "kind": kind, "payload": payload, "max_attempts": max_attempts})
        old = self.request_log.get(operation_id)
        if old is not None:
            if old["fingerprint"] != fingerprint:
                raise IntegrationError("changed_authority_replay")
            return deepcopy(old["result"])
        status = self.responses.pop(0) if self.responses else "unknown"
        if status not in {"accepted", "pending", "rejected", "timeout", "unknown"}:
            raise IntegrationError("ambiguous_authority_result")
        result = {"authority": "awq", "operation_id": operation_id, "status": status, "binding_digest": self.binding_digest or payload["binding_digest"], "result_digest": digest({"operation_id": operation_id, "status": status})}
        self.request_log[operation_id] = {"fingerprint": fingerprint, "result": deepcopy(result)}
        if status == "pending":
            self.completed.pop(operation_id, None)
        elif status == "accepted":
            self.completed[operation_id] = deepcopy(result)
        return result

    def observe(self, operation_id: str) -> dict[str, Any]:
        if operation_id not in self.request_log:
            raise IntegrationError("unknown_authority_operation")
        return deepcopy(self.completed.get(operation_id, self.request_log[operation_id]["result"]))

    def resolve(self, operation_id: str, status: str = "accepted") -> None:
        if operation_id not in self.request_log or status not in {"accepted", "rejected", "timeout", "unknown"}:
            raise IntegrationError("invalid_authority_resolution")
        result = deepcopy(self.request_log[operation_id]["result"])
        result["status"] = status
        result["result_digest"] = digest({"operation_id": operation_id, "status": status})
        self.completed[operation_id] = result


class LocalProjectFake:
    """Generic project fake with deterministic response record/replay."""

    def __init__(self, runtime: ProjectIntegrationRuntime):
        self.runtime = runtime
        self.recorded: list[dict[str, Any]] = []

    def record(self, operation: str, request: Any, response: Any) -> dict[str, Any]:
        entry = {"operation": operation, "request_digest": digest(request), "response": deepcopy(response)}
        self.recorded.append(entry)
        return deepcopy(entry)

    def replay(self, operation: str, request: Any) -> Any:
        request_digest = digest(request)
        matches = [entry for entry in self.recorded if entry["operation"] == operation and entry["request_digest"] == request_digest]
        if not matches:
            raise IntegrationError("replay_miss")
        return deepcopy(matches[-1]["response"])


__all__ = [
    "DIGEST",
    "PROTOCOL",
    "TASK",
    "EvidenceEnvelope",
    "IntegrationError",
    "LocalAuthorityPort",
    "LocalProjectFake",
    "ProjectIntegrationRuntime",
    "ProjectRegistration",
    "SessionBoundary",
    "TaskIntake",
    "TerminalObservation",
    "canonical",
    "digest",
]

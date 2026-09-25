"""AR-0131: the first executable, revision-bound local agent controller.

Only the deterministic fake profile is executable here.  Provider, credential,
key, and model configuration are deliberately not inputs to this boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from awr_cli.agent_registry import AdapterRegistry, RegistryError
from scripts.durable_coordinator import AuthorityError, Coordinator
from scripts.worker_monitor import MonitorPolicy, RecoveryStore, WorkerMonitor

from .host_sandbox import HostSandbox, SandboxBudget, SandboxError


class ExecutionError(ValueError):
    """Fail-closed admission, binding, evidence, or execution error."""


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TASK = re.compile(r"^AR-[0-9]{4}$")
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_WORKTREE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_SESSION = re.compile(r"^SES-[A-Z0-9-]{3,64}$")
_WORKER = re.compile(r"^WRK-[A-Z0-9-]{1,63}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class ExecutionBinding:
    task_id: str
    task_revision: int
    project_key: str
    project_revision: str
    worktree_key: str
    worktree_digest: str
    session_id: str

    def validate(self) -> None:
        if not _TASK.fullmatch(self.task_id) or isinstance(self.task_revision, bool) or not isinstance(self.task_revision, int) or self.task_revision < 1:
            raise ExecutionError("task_binding_invalid")
        if not _PROJECT.fullmatch(self.project_key) or not _DIGEST.fullmatch(self.project_revision):
            raise ExecutionError("project_binding_invalid")
        if not _WORKTREE.fullmatch(self.worktree_key) or not _DIGEST.fullmatch(self.worktree_digest):
            raise ExecutionError("worktree_binding_invalid")
        if not _SESSION.fullmatch(self.session_id):
            raise ExecutionError("session_binding_invalid")


class ExecutionController:
    """Admit and run exactly one deterministic local fake agent session."""

    def __init__(self, *, registry: AdapterRegistry, evidence_dir: Path, coordinator: Coordinator, owner_id: str, clock=time.time):
        self.registry = registry
        self.evidence_dir = Path(evidence_dir).resolve()
        self.coordinator = coordinator
        if not isinstance(owner_id, str) or not _WORKER.fullmatch(owner_id):
            raise ExecutionError("owner_binding_invalid")
        self.owner_id = owner_id
        self.clock = clock

    @staticmethod
    def _validate_authority(admission: dict[str, Any], binding: ExecutionBinding) -> None:
        if not isinstance(admission, dict) or admission.get("status") != "admitted" or admission.get("task") != binding.task_id or admission.get("task_revision") != binding.task_revision or admission.get("authority_state") != "observed_only":
            raise ExecutionError("authority_admission_invalid")
        if admission.get("mandatory_order") != ["coordinator", "awq", "awg", "ui"] or admission.get("decision") != "approved":
            raise ExecutionError("authority_admission_incomplete")
        trace = admission.get("trace")
        if not isinstance(trace, list) or len(trace) != 4 or any(not isinstance(item, dict) for item in trace):
            raise ExecutionError("authority_trace_invalid")

    def _profile(self, adapter_id: str, registry_revision: int, capabilities: list[str]) -> dict[str, Any]:
        try:
            negotiated = self.registry.negotiate(adapter_id, capabilities, expected_revision=registry_revision)
            profile = self.registry.profile(adapter_id)
        except RegistryError as exc:
            raise ExecutionError(f"registry_{exc}") from exc
        if profile.adapter_id != adapter_id or profile.command_profile != ("deterministic-agent",) or profile.sandbox_required is not True:
            raise ExecutionError("registry_profile_not_executable")
        return negotiated

    def run(
        self,
        *,
        binding: ExecutionBinding,
        authority_admission: dict[str, Any],
        worktree: Path,
        adapter_id: str,
        registry_revision: int,
        capabilities: list[str] | None = None,
        budget: SandboxBudget | None = None,
        cancel_requested=None,
        monitor_policy: MonitorPolicy | None = None,
        reconcile_terminal: bool = True,
        lease_observer=None,
        recovered_lease: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(reconcile_terminal, bool):
            raise ExecutionError("terminal_reconciliation_option_invalid")
        binding.validate()
        self._validate_authority(authority_admission, binding)
        root = Path(worktree).resolve(strict=True)
        if not root.is_dir():
            raise ExecutionError("worktree_invalid")
        negotiated = self._profile(adapter_id, registry_revision, capabilities or ["request", "close"])
        selected_budget = budget or SandboxBudget()
        selected_budget.validate()
        try:
            sandbox = HostSandbox(root)
        except SandboxError as exc:
            raise ExecutionError("sandbox_admission_failed") from exc

        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # Caller-provided lease blobs are observations only. Coordinator owns
        # task revision, claim, fencing token, and expiry for this session.
        try:
            task = self.coordinator.read_task(binding.task_id)
            if task.get("task_revision", task["revision"]) != binding.task_revision or task["project_revision"] != binding.project_revision or task["worktree_digest"] != binding.worktree_digest:
                raise ExecutionError("coordinator_task_binding_mismatch")
            if recovered_lease is None:
                claim = self._authority_write(lambda: self.coordinator.claim(binding.task_id, task["revision"], self.owner_id, f"OP-{binding.session_id}-CLAIM"))
                coordinator_lease = self._authority_write(lambda: self.coordinator.acquire_lease(binding.task_id, claim["revision"], self.owner_id, binding.session_id, f"OP-{binding.session_id}-LEASE"))
                lease_value = coordinator_lease.get("lease")
                if not isinstance(lease_value, dict):
                    lease_value = self.coordinator.read_task(binding.task_id).get("lease")
                authoritative_revision = coordinator_lease["revision"]
            else:
                latest = self.coordinator.read_task(binding.task_id)
                lease_value = latest.get("lease")
                if (latest.get("status") != "running" or lease_value != recovered_lease
                        or lease_value.get("owner") != self.owner_id or lease_value.get("session") != binding.session_id):
                    raise ExecutionError("recovered_coordinator_lease_mismatch")
                authoritative_revision = latest["revision"]
            if not isinstance(lease_value, dict):
                raise ExecutionError("coordinator_lease_missing")
            if lease_observer is not None:
                lease_observer(lease_value, authoritative_revision)
        except AuthorityError as exc:
            raise ExecutionError(f"coordinator_{exc}") from exc
        evidence = self.evidence_dir / f"{binding.session_id}-F{lease_value['fence']}.json"
        checkpoint_path = self.evidence_dir / f"{binding.session_id}.checkpoint.json"
        if evidence.exists():
            raise ExecutionError("session_evidence_replayed")
        argv = ["/usr/bin/python3", "-c", "import sys; print('{\"type\":\"message\",\"data\":{\"text\":\"AWR-FAKE-AGENT-OK\"}}'); print('{\"type\":\"state\",\"data\":{\"state\":\"AWR-FAKE-AGENT-ERR\"}}', file=sys.stderr)"]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "PYTHONUNBUFFERED": "1", "AWR_SESSION_ID": binding.session_id, "AWR_TASK_REVISION": str(binding.task_revision)}
        spawn = {
            "schema_version": 1, "event": "spawned", "task": binding.task_id, "task_revision": binding.task_revision,
            "project_key": binding.project_key, "project_revision": binding.project_revision, "worktree_key": binding.worktree_key,
            "worktree_digest": binding.worktree_digest, "session_id": binding.session_id, "lease_id": lease_value["id"],
            "worker_id": self.owner_id, "lease_fence": lease_value["fence"], "profile_digest": negotiated["profile_digest"],
            "registry_revision": negotiated["registry_revision"], "argv_digest": _digest(argv), "environment_names": sorted(environment),
            "stdio": {"stdin": "pipe", "stdout": "pipe", "stderr": "pipe"}, "process_group": "session-leader",
            "controls": sandbox.capabilities.as_dict(), "provider": "not_performed", "configuration": "not_inspected",
        }
        process = None
        try:
            authoritative_revision = self._coordinator_event(binding, authoritative_revision, lease_value, "session_started", _digest({"session": binding.session_id, "profile": negotiated["profile_digest"]}))
            heartbeat = self._authority_write(lambda: self.coordinator.heartbeat(binding.task_id, authoritative_revision, lease_value, f"OP-{binding.session_id}-F{lease_value['fence']}-HEARTBEAT"))
            lease_value = heartbeat["lease"]
            authoritative_revision = heartbeat["revision"]
            process = sandbox.launch(argv, budget=selected_budget, environment=environment)
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise ExecutionError("stdio_binding_invalid")
            process.stdin.close()
            spawn.update({"pid": process.pid, "pgid": os.getpgid(process.pid)})
            _atomic_json(evidence, {"spawn": spawn})
            recovery = RecoveryStore(checkpoint_path)
            heartbeat_number = 0

            def renew_lease():
                nonlocal authoritative_revision, lease_value, heartbeat_number
                current = self.coordinator.read_task(binding.task_id)
                if current.get("lease") != lease_value:
                    raise ExecutionError("coordinator_lease_expired_or_fenced")
                heartbeat_number += 1
                receipt = self._authority_write(lambda: self.coordinator.heartbeat(
                    binding.task_id, current["revision"], lease_value,
                    f"OP-{binding.session_id}-F{lease_value['fence']}-MONITOR-{heartbeat_number:06d}"))
                lease_value = receipt["lease"]
                authoritative_revision = receipt["revision"]

            checkpoint_binding = {"task_id": binding.task_id, "task_revision": binding.task_revision,
                "session_id": binding.session_id, "worktree_digest": binding.worktree_digest,
                "worker_id": self.owner_id, "lease_id": lease_value["id"], "lease_fence": lease_value["fence"]}
            observed = WorkerMonitor(clock=time.monotonic, policy=monitor_policy or MonitorPolicy(),
                heartbeat=renew_lease, cancel_requested=cancel_requested,
                checkpoint=lambda state: recovery.checkpoint(checkpoint_binding, state)).wait(
                    process, timeout=selected_budget.timeout_seconds, output_limit=selected_budget.output_bytes)
            stdout, stderr = observed["stdout"], observed["stderr"]
            timed_out = observed["timed_out"] or observed["stalled"]
            overflow = observed["output_overflow"]
            terminal = {
                "schema_version": 1, "event": "terminal", "status": "cleanup_unconfirmed" if not observed["process_group_clean"] else ("cancelled" if observed["cancelled"] else ("stalled" if observed["stalled"] else ("timeout" if timed_out else ("output_overflow" if overflow else ("completed" if process.returncode == 0 else "failed"))))),
                "returncode": process.returncode, "stdout_digest": _digest(stdout.decode("utf-8", "replace")), "stderr_digest": _digest(stderr.decode("utf-8", "replace")),
                "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "process_tree_clean": observed["process_group_clean"],
                "cleanup": observed["process_group_clean"], "lease_id": lease_value["id"],
                "monitor": {key: observed[key] for key in ("heartbeat_count", "progress_observed", "resource_observation", "process_group_clean")},
            }
            authoritative_revision = self._coordinator_event(binding, authoritative_revision, lease_value, "session_terminal", _digest({"status": terminal["status"], "stdout": terminal["stdout_digest"], "stderr": terminal["stderr_digest"]}))
            snapshot = self.coordinator.read_task(binding.task_id)
            authoritative_revision = snapshot["revision"]
            status = "done" if terminal["status"] == "completed" else "failed"
            if reconcile_terminal:
                self._authority_write(lambda: self.coordinator.reconcile(binding.task_id, authoritative_revision, lease_value, status, f"OP-{binding.session_id}-F{lease_value['fence']}-RECONCILE"))
            _atomic_json(evidence, {"spawn": spawn, "terminal": terminal})
            return {"status": terminal["status"], "session_id": binding.session_id, "evidence": str(evidence), "spawn": spawn, "terminal": terminal, "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace"),
                    "coordinator_lease": lease_value if not reconcile_terminal else None,
                    "coordinator_revision": authoritative_revision if not reconcile_terminal else None,
                    "lease_expires_at": lease_value["expires_at"] if not reconcile_terminal else None,
                    "reconciliation_pending": not reconcile_terminal}
        except (OSError, SandboxError, ExecutionError, AuthorityError):
            if process is not None and process.poll() is None:
                sandbox.cancel(process)
            # A started session must leave an authoritative failure request
            # when the lease is still current. If authority is unavailable,
            # retain the original failure and never infer terminal success.
            try:
                latest = self.coordinator.read_task(binding.task_id)
                current_lease = latest.get("lease")
                if isinstance(current_lease, dict) and current_lease == lease_value:
                    rev = latest["revision"]
                    failed = _digest({"status": "failed", "session": binding.session_id})
                    suffix = f"-F{current_lease['fence']}"
                    receipt = self.coordinator.append_session_event(binding.task_id, rev, current_lease, binding.session_id, "session_terminal", failed, f"OP-{binding.session_id}{suffix}-FAILURE-TERMINAL")
                    self.coordinator.reconcile(binding.task_id, receipt["revision"], current_lease, "failed", f"OP-{binding.session_id}{suffix}-FAILURE-RECONCILE")
            except (AuthorityError, KeyError, TypeError):
                pass
            raise

    def recover(self, *, task_id: str, session_id: str, owner_id: str, checkpoint_path: Path,
                attempts: int = 0) -> dict[str, Any]:
        """Acquire a fresh Coordinator fence and verify the latest checkpoint."""
        recovery = RecoveryStore(checkpoint_path)
        stored = recovery.inspect()
        prior = stored.get("binding", {})
        if prior.get("task_id") != task_id or prior.get("session_id") != session_id:
            raise ExecutionError("checkpoint_binding_mismatch")
        try:
            task = self.coordinator.read_task(task_id)
            old_lease = task.get("lease")
            if not isinstance(old_lease, dict) or old_lease.get("fence") != prior.get("lease_fence"):
                raise ExecutionError("coordinator_recovery_fence_mismatch")
            receipt = self._authority_write(lambda: self.coordinator.recover_expired(
                task_id, task["revision"], owner_id, session_id,
                f"OP-{session_id}-RECOVER-{old_lease['fence']}"))
        except AuthorityError as exc:
            raise ExecutionError(f"coordinator_{exc}") from exc
        lease = receipt.get("lease")
        if not isinstance(lease, dict):
            lease = self.coordinator.read_task(task_id).get("lease")
        if not isinstance(lease, dict):
            raise ExecutionError("coordinator_recovery_lease_missing")
        binding = {**prior, "worker_id": owner_id, "lease_id": lease["id"], "lease_fence": lease["fence"]}
        try:
            recovered = recovery.recover(binding=binding, attempts=attempts, old_fence=prior["lease_fence"])
        except ValueError as exc:
            raise ExecutionError(f"recovery_{exc}") from exc
        return {"status": "recovered", "task_revision": receipt["revision"], "lease": lease,
                "checkpoint_digest": stored["checkpoint_digest"], "attempt": recovered["attempt"],
                "resume_state_digest": stored["state_digest"], "provider": "not_performed"}

    def _coordinator_event(self, binding, revision, lease, event, event_digest):
        try:
            receipt = self._authority_write(lambda: self.coordinator.append_session_event(binding.task_id, revision, lease, binding.session_id, event, event_digest, f"OP-{binding.session_id}-F{lease['fence']}-{event.upper().replace('_', '-')}"))
            return receipt["revision"]
        except AuthorityError as exc:
            raise ExecutionError(f"coordinator_{exc}") from exc

    @staticmethod
    def _authority_write(operation):
        try:
            return operation()
        except AuthorityError as exc:
            if str(exc) != "unknown_outcome":
                raise
            # Resolve only by retrying the exact same operation ID and payload;
            # the authority fake returns its durable idempotency receipt.
            return operation()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".execution-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


__all__ = ["ExecutionBinding", "ExecutionController", "ExecutionError"]

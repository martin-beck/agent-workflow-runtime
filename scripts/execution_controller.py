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

from .host_sandbox import HostSandbox, SandboxBudget, SandboxError


class ExecutionError(ValueError):
    """Fail-closed admission, binding, evidence, or execution error."""


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TASK = re.compile(r"^AR-[0-9]{4}$")
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_WORKTREE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_SESSION = re.compile(r"^SES-[A-Z0-9-]{3,64}$")
_WORKER = re.compile(r"^WRK-[A-Z0-9-]{1,63}$")
_LEASE = re.compile(r"^LSE-[A-Z0-9-]{1,63}$")


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


@dataclass(frozen=True)
class JobLease:
    lease_id: str
    worker_id: str
    fence: int
    expires_at: float

    def validate(self, now: float) -> None:
        if not _LEASE.fullmatch(self.lease_id) or not _WORKER.fullmatch(self.worker_id):
            raise ExecutionError("lease_binding_invalid")
        if isinstance(self.fence, bool) or not isinstance(self.fence, int) or self.fence < 1:
            raise ExecutionError("lease_fence_invalid")
        if not isinstance(self.expires_at, (int, float)) or isinstance(self.expires_at, bool) or self.expires_at <= now:
            raise ExecutionError("lease_stale")


def _load_lease(value: dict[str, Any]) -> JobLease:
    required = {"id", "worker", "fence", "expires_at"}
    if not isinstance(value, dict) or set(value) != required:
        raise ExecutionError("lease_shape_invalid")
    return JobLease(str(value["id"]), str(value["worker"]), value["fence"], value["expires_at"])


class ExecutionController:
    """Admit and run exactly one deterministic local fake agent session."""

    def __init__(self, *, registry: AdapterRegistry, evidence_dir: Path, clock=time.time):
        self.registry = registry
        self.evidence_dir = Path(evidence_dir).resolve()
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
        lease: dict[str, Any],
        authority_admission: dict[str, Any],
        worktree: Path,
        adapter_id: str,
        registry_revision: int,
        capabilities: list[str] | None = None,
        budget: SandboxBudget | None = None,
    ) -> dict[str, Any]:
        binding.validate()
        now = self.clock()
        job_lease = _load_lease(lease)
        job_lease.validate(now)
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
        evidence = self.evidence_dir / f"{binding.session_id}.json"
        if evidence.exists():
            raise ExecutionError("session_evidence_replayed")
        argv = ["/usr/bin/python3", "-c", "import os; print('AWR-FAKE-AGENT-OK'); print('AWR-FAKE-AGENT-ERR', file=__import__('sys').stderr)"]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "PYTHONUNBUFFERED": "1", "AWR_SESSION_ID": binding.session_id, "AWR_TASK_REVISION": str(binding.task_revision)}
        spawn = {
            "schema_version": 1, "event": "spawned", "task": binding.task_id, "task_revision": binding.task_revision,
            "project_key": binding.project_key, "project_revision": binding.project_revision, "worktree_key": binding.worktree_key,
            "worktree_digest": binding.worktree_digest, "session_id": binding.session_id, "lease_id": job_lease.lease_id,
            "worker_id": job_lease.worker_id, "lease_fence": job_lease.fence, "profile_digest": negotiated["profile_digest"],
            "registry_revision": negotiated["registry_revision"], "argv_digest": _digest(argv), "environment_names": sorted(environment),
            "stdio": {"stdin": "pipe", "stdout": "pipe", "stderr": "pipe"}, "process_group": "session-leader",
            "controls": sandbox.capabilities.as_dict(), "provider": "not_performed", "configuration": "not_inspected",
        }
        process = None
        try:
            process = sandbox.launch(argv, budget=selected_budget, environment=environment)
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise ExecutionError("stdio_binding_invalid")
            process.stdin.close()
            spawn.update({"pid": process.pid, "pgid": os.getpgid(process.pid)})
            _atomic_json(evidence, {"spawn": spawn})
            stdout, stderr, timed_out, overflow = sandbox.wait(process, budget=selected_budget)
            terminal = {
                "schema_version": 1, "event": "terminal", "status": "timeout" if timed_out else ("output_overflow" if overflow else ("completed" if process.returncode == 0 else "failed")),
                "returncode": process.returncode, "stdout_digest": _digest(stdout.decode("utf-8", "replace")), "stderr_digest": _digest(stderr.decode("utf-8", "replace")),
                "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "process_tree_clean": process.poll() is not None,
                "cleanup": process.poll() is not None, "lease_id": job_lease.lease_id,
            }
            _atomic_json(evidence, {"spawn": spawn, "terminal": terminal})
            return {"status": terminal["status"], "session_id": binding.session_id, "evidence": str(evidence), "spawn": spawn, "terminal": terminal, "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace")}
        except (OSError, SandboxError, ExecutionError):
            if process is not None and process.poll() is None:
                sandbox.cancel(process)
            raise


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


__all__ = ["ExecutionBinding", "ExecutionController", "ExecutionError", "JobLease"]

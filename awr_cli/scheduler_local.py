"""Persistent deterministic local scheduler with fenced worker leases."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .agent_registry import AdapterRegistry, RegistryError

from .cli import CliError, canonical


def _digest(value: Any) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class LocalScheduler:
    def __init__(self, path: Path, max_concurrency: int = 2, *, registry: AdapterRegistry | None = None):
        self.path = path.expanduser().absolute(); self.lock = self.path.with_suffix(self.path.suffix + ".lock")
        self.max_concurrency = max_concurrency
        self.registry = registry or AdapterRegistry.memory_with_fakes()
        if self.path.is_symlink() or self.lock.is_symlink(): raise CliError("scheduler_state_symlink")

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock.open("a+") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists(): return {"schema_version": 1, "fence": 0, "jobs": {}, "events": []}
        try: value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise CliError("scheduler_state_corrupt") from exc
        if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("jobs"), dict) or not isinstance(value.get("events"), list): raise CliError("scheduler_state_incompatible")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        fd, name = tempfile.mkstemp(prefix=".scheduler-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":")); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
        except BaseException:
            try: os.unlink(name)
            except OSError: pass
            raise

    @staticmethod
    def _view(value: dict[str, Any]) -> dict[str, Any]:
        return {"jobs": value["jobs"], "events": len(value["events"]), "fence": value["fence"], "state_digest": _digest(value), "network": "disabled", "provider": "not_performed"}

    def submit(self, job_id: str, project: str, dependencies: list[str] | None = None, priority: int = 50, retry_limit: int = 1, *, adapter_id: str = "fake-alpha", capabilities: list[str] | None = None) -> dict[str, Any]:
        dependencies = list(dependencies or [])
        if not job_id.startswith("JOB-") or not project or job_id in dependencies or len(set(dependencies)) != len(dependencies) or not 0 <= priority <= 100 or retry_limit < 0:
            raise CliError("scheduler_job_invalid")
        try:
            negotiation = self.registry.negotiate(adapter_id, capabilities or ["request"])
        except RegistryError as exc:
            raise CliError(f"scheduler_{exc}") from exc
        with self._locked():
            value = self._load()
            if job_id in value["jobs"]: raise CliError("scheduler_job_duplicate")
            if any(dep not in value["jobs"] for dep in dependencies): raise CliError("scheduler_dependency_missing")
            value["jobs"][job_id] = {"job_id": job_id, "project": project, "dependencies": dependencies, "priority": priority, "retry_limit": retry_limit, "attempts": 0, "state": "queued" if not dependencies else "waiting", "lease": None, "adapter_id": adapter_id, "capabilities": negotiation["capabilities"], "registry_revision": negotiation["registry_revision"], "profile_digest": negotiation["profile_digest"]}
            value["events"].append({"kind": "submitted", "job_id": job_id})
            self._save(value); return self._view(value)

    def dispatch(self, worker_id: str) -> dict[str, Any]:
        if not worker_id.startswith("WRK-"): raise CliError("scheduler_worker_invalid")
        with self._locked():
            value = self._load(); running = [job for job in value["jobs"].values() if job["state"] == "running"]
            if len(running) >= self.max_concurrency: raise CliError("scheduler_capacity_exhausted")
            for job in value["jobs"].values():
                if job["state"] == "waiting" and all(value["jobs"][dep]["state"] == "done" for dep in job["dependencies"]): job["state"] = "queued"
            ready = [job for job in value["jobs"].values() if job["state"] == "queued"]
            if not ready: raise CliError("scheduler_no_ready_job")
            job = sorted(ready, key=lambda item: (-item["priority"], item["attempts"], item["job_id"]))[0]
            try:
                negotiation = self.registry.negotiate(job["adapter_id"], job["capabilities"], expected_revision=job["registry_revision"])
            except RegistryError as exc:
                raise CliError(f"scheduler_{exc}") from exc
            if negotiation["profile_digest"] != job["profile_digest"]:
                raise CliError("scheduler_stale_profile")
            value["fence"] += 1; job["attempts"] += 1; job["state"] = "running"; job["lease"] = {"id": f"LSE-{value['fence']:08d}", "worker": worker_id, "fence": value["fence"]}
            value["events"].append({"kind": "dispatched", "job_id": job["job_id"], "lease": job["lease"]})
            self._save(value); return {"job": job.copy(), **self._view(value)}

    def complete(self, job_id: str, worker_id: str, lease_id: str, status: str = "done") -> dict[str, Any]:
        if status not in {"done", "failed"}: raise CliError("scheduler_terminal_invalid")
        with self._locked():
            value = self._load(); job = value["jobs"].get(job_id)
            if job is None or job["state"] != "running" or not job["lease"] or job["lease"]["worker"] != worker_id or job["lease"]["id"] != lease_id: raise CliError("scheduler_lease_fence_mismatch")
            if status == "failed" and job["attempts"] <= job["retry_limit"]: job["state"] = "queued"; job["lease"] = None; kind = "retry"
            else: job["state"] = status; job["lease"] = None; kind = "completed"
            value["events"].append({"kind": kind, "job_id": job_id, "status": job["state"]})
            self._save(value); return self._view(value)

    def status(self) -> dict[str, Any]:
        with self._locked(): return self._view(self._load())

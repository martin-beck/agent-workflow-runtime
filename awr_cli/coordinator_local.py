"""Persistent local Coordinator-shaped state adapter for offline qualification."""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .cli import CliError, canonical

ID = re.compile(r"^(?:AR|JOB|SES|WRK)-[A-Z0-9-]{1,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _digest(value: Any) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class LocalCoordinator:
    def __init__(self, state_file: Path):
        self.path = state_file.expanduser().absolute()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        if self.path.is_symlink() or self.lock_path.is_symlink():
            raise CliError("coordinator_state_symlink")

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            raise CliError("coordinator_state_missing")
        try: value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise CliError("coordinator_state_corrupt") from exc
        if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("task"), dict) or not isinstance(value.get("events"), list):
            raise CliError("coordinator_state_incompatible")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        fd, name = tempfile.mkstemp(prefix=".coordinator-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":")); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
        except BaseException:
            try: os.unlink(name)
            except OSError: pass
            raise

    def init(self, task_id: str, project_revision: str, worktree_digest: str, session_id: str) -> dict[str, Any]:
        if not ID.fullmatch(task_id) or not DIGEST.fullmatch(project_revision) or not DIGEST.fullmatch(worktree_digest) or not ID.fullmatch(session_id):
            raise CliError("coordinator_binding_invalid")
        with self._locked():
            if self.path.exists(): raise CliError("coordinator_state_exists")
            value = {"schema_version": 1, "authority": "coordinator", "task": {"id": task_id, "revision": 1, "status": "open", "owner": None, "lease": None, "fence": 0, "project_revision": project_revision, "worktree_digest": worktree_digest, "session_id": session_id}, "events": []}
            self._save(value)
            return self._snapshot_value(value)

    def snapshot(self) -> dict[str, Any]:
        with self._locked():
            return self._snapshot_value(self._load())

    @staticmethod
    def _snapshot_value(value: dict[str, Any]) -> dict[str, Any]:
        return {"task": value["task"], "events": len(value["events"]), "state_digest": _digest(value), "authority": "coordinator", "network": "disabled"}

    def claim(self, owner: str, expected_revision: int) -> dict[str, Any]:
        if not ID.fullmatch(owner): raise CliError("owner_invalid")
        with self._locked():
            value = self._load(); task = value["task"]
            if task["revision"] != expected_revision: raise CliError("stale_coordinator_revision")
            if task["status"] != "open" or task["owner"] is not None: raise CliError("task_not_claimable")
            task["revision"] += 1; task["owner"] = owner; task["fence"] += 1; task["lease"] = f"LSE-{task['fence']:08d}"
            value["events"].append({"kind": "claimed", "revision": task["revision"], "owner": owner, "fence": task["fence"]})
            self._save(value); return self._snapshot_value(value)

    def heartbeat(self, owner: str, lease: str, expected_revision: int) -> dict[str, Any]:
        with self._locked():
            value = self._load(); task = value["task"]
            if task["revision"] != expected_revision or task["owner"] != owner or task["lease"] != lease: raise CliError("lease_fence_mismatch")
            value["events"].append({"kind": "heartbeat", "revision": task["revision"], "owner": owner, "fence": task["fence"]})
            self._save(value); return self._snapshot_value(value)

    def complete(self, owner: str, lease: str, expected_revision: int, status: str = "done") -> dict[str, Any]:
        if status not in {"done", "blocked"}: raise CliError("terminal_status_invalid")
        with self._locked():
            value = self._load(); task = value["task"]
            if task["revision"] != expected_revision or task["owner"] != owner or task["lease"] != lease: raise CliError("lease_fence_mismatch")
            task["revision"] += 1; task["status"] = status; task["lease"] = None
            value["events"].append({"kind": "terminal", "revision": task["revision"], "owner": owner, "status": status, "fence": task["fence"]})
            self._save(value); return self._snapshot_value(value)

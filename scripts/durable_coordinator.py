"""Durable Coordinator-shaped execution authority for deterministic tests.

The interface deliberately represents requests to authority. The file-backed
implementation is a CI fake, not a hosted Coordinator or production transport.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Protocol


class AuthorityError(ValueError):
    pass


class Coordinator(Protocol):
    def read_task(self, task_id: str) -> dict[str, Any]: ...
    def claim(self, task_id: str, revision: int, owner: str, operation_id: str) -> dict[str, Any]: ...
    def acquire_lease(self, task_id: str, revision: int, owner: str, session: str, operation_id: str) -> dict[str, Any]: ...
    def heartbeat(self, task_id: str, revision: int, lease: dict[str, Any], operation_id: str) -> dict[str, Any]: ...
    def append_session_event(self, task_id: str, revision: int, lease: dict[str, Any], session: str, event: str, event_digest: str, operation_id: str) -> dict[str, Any]: ...
    def reconcile(self, task_id: str, revision: int, lease: dict[str, Any], status: str, operation_id: str) -> dict[str, Any]: ...


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class DurableFakeCoordinator:
    """Atomic, restartable authority fake with CAS, fencing and idempotent ops."""

    def __init__(self, path: Path, *, clock, lease_seconds: float = 30):
        self.path = Path(path).absolute()
        self.lock = self.path.with_suffix(self.path.suffix + ".lock")
        self.clock = clock
        self.lease_seconds = lease_seconds
        if self.path.is_symlink() or self.lock.is_symlink() or lease_seconds <= 0:
            raise AuthorityError("state_binding_invalid")

    def initialize(self, task_id: str, revision: int, project_revision: str, worktree_digest: str) -> None:
        if not task_id.startswith("AR-") or revision < 1:
            raise AuthorityError("task_binding_invalid")
        with self._locked():
            if self.path.exists():
                raise AuthorityError("state_already_initialized")
            self._save({"schema": 1, "task": {"id": task_id, "revision": revision, "status": "open", "project_revision": project_revision, "worktree_digest": worktree_digest, "owner": None, "lease": None, "fence": 0}, "events": [], "operations": {}})

    def _locked(self):
        coordinator = self
        class Lock:
            def __enter__(self):
                coordinator.path.parent.mkdir(parents=True, exist_ok=True)
                self.handle = coordinator.lock.open("a+")
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                return self
            def __exit__(self, *_):
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN); self.handle.close()
        return Lock()

    def _load(self):
        try: value = json.loads(self.path.read_text())
        except (OSError, ValueError) as exc: raise AuthorityError("authority_state_unavailable") from exc
        if not isinstance(value, dict) or value.get("schema") != 1: raise AuthorityError("authority_state_invalid")
        return value

    def _save(self, value):
        fd, name = tempfile.mkstemp(prefix=".coordinator-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":")); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
            directory = os.open(self.path.parent, os.O_DIRECTORY); os.fsync(directory); os.close(directory)
        finally:
            if os.path.exists(name): os.unlink(name)

    def _operation(self, value, op, fingerprint, action):
        old = value["operations"].get(op)
        if old:
            if old["fingerprint"] != fingerprint: raise AuthorityError("operation_id_conflict")
            return old["receipt"]
        receipt = action()
        value["operations"][op] = {"fingerprint": fingerprint, "receipt": receipt}
        self._save(value)
        if getattr(self, "ambiguous_once", False):
            self.ambiguous_once = False
            raise AuthorityError("unknown_outcome")
        return receipt

    def read_task(self, task_id):
        with self._locked():
            task = self._load()["task"]
            if task["id"] != task_id: raise AuthorityError("task_not_found")
            return dict(task)

    def claim(self, task_id, revision, owner, operation_id):
        with self._locked():
            value = self._load(); task = value["task"]
            def action():
                self._cas(task, task_id, revision)
                if task["status"] != "open" or task["owner"] is not None: raise AuthorityError("task_not_claimable")
                task.update(revision=revision + 1, owner=owner, status="claimed")
                return self._record(value, "claimed", task_id=task_id, task_revision=revision, owner=owner)
            return self._operation(value, operation_id, _digest(["claim", task_id, revision, owner]), action)

    def acquire_lease(self, task_id, revision, owner, session, operation_id):
        with self._locked():
            value = self._load(); task = value["task"]
            def action():
                self._cas(task, task_id, revision)
                if task["owner"] != owner or task["status"] != "claimed": raise AuthorityError("claim_mismatch")
                task["fence"] += 1
                task["revision"] += 1
                task["status"] = "running"
                task["lease"] = {"id": f"LSE-{task['fence']:08d}", "owner": owner, "fence": task["fence"], "expires_at": self.clock() + self.lease_seconds, "session": session}
                return self._record(value, "lease_acquired", task_id=task_id, task_revision=revision, session=session, lease=dict(task["lease"]))
            return self._operation(value, operation_id, _digest(["lease", task_id, revision, owner, session]), action)

    def heartbeat(self, task_id, revision, lease, operation_id):
        with self._locked():
            value = self._load(); task = value["task"]
            def action():
                self._guard(task, task_id, revision, lease)
                task["revision"] += 1; task["lease"]["expires_at"] = self.clock() + self.lease_seconds
                receipt = self._record(value, "heartbeat", task_id=task_id, task_revision=revision, lease=lease["id"], fence=lease["fence"])
                receipt["lease"] = dict(task["lease"])
                return receipt
            return self._operation(value, operation_id, _digest(["heartbeat", task_id, revision, lease]), action)

    def append_session_event(self, task_id, revision, lease, session, event, event_digest, operation_id):
        if not isinstance(event, str) or not event.replace("_", "").isalnum() or not isinstance(event_digest, str) or not event_digest.startswith("sha256:"):
            raise AuthorityError("session_event_invalid")
        with self._locked():
            value = self._load(); task = value["task"]
            def action():
                self._guard(task, task_id, revision, lease)
                if task["lease"].get("session") != session: raise AuthorityError("session_mismatch")
                task["revision"] += 1
                return self._record(value, "session_event", task_id=task_id, task_revision=revision, session=session, event=event, event_digest=event_digest, lease=lease["id"], fence=lease["fence"])
            return self._operation(value, operation_id, _digest(["event", task_id, revision, lease, session, event, event_digest]), action)

    def reconcile(self, task_id, revision, lease, status, operation_id):
        if status not in {"done", "blocked", "failed"}: raise AuthorityError("terminal_status_invalid")
        with self._locked():
            value = self._load(); task = value["task"]
            def action():
                self._guard(task, task_id, revision, lease)
                task.update(revision=revision + 1, status=status, lease=None, owner=None)
                return self._record(value, "reconciled", task_id=task_id, task_revision=revision, status=status, lease=lease["id"], fence=lease["fence"])
            return self._operation(value, operation_id, _digest(["reconcile", task_id, revision, lease, status]), action)

    def _record(self, value, kind, **fields):
        item = {"sequence": len(value["events"]) + 1, "kind": kind, **fields}
        item["digest"] = _digest(item); value["events"].append(item)
        return {"revision": value["task"]["revision"], "event_count": len(value["events"]), "receipt_digest": item["digest"], **fields}

    def _cas(self, task, task_id, revision):
        if task["id"] != task_id: raise AuthorityError("task_not_found")
        if task["revision"] != revision: raise AuthorityError("cas_conflict")

    def _guard(self, task, task_id, revision, lease):
        self._cas(task, task_id, revision)
        if task["lease"] != lease or lease["expires_at"] <= self.clock(): raise AuthorityError("lease_expired_or_fenced")

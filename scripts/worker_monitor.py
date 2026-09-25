"""Live process monitoring and fenced recovery primitives for AR-0134.

The monitor records bounded observations only. Coordinator remains the source
of task and lease authority; callbacks supplied by the controller perform its
durable heartbeat and event operations.
"""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class MonitorError(ValueError):
    pass


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class MonitorPolicy:
    heartbeat_seconds: float = 0.25
    output_stall_seconds: float = 2.0
    terminate_grace_seconds: float = 0.2

    def validate(self) -> None:
        if any(not isinstance(v, (int, float)) or v <= 0 for v in (self.heartbeat_seconds, self.output_stall_seconds, self.terminate_grace_seconds)):
            raise MonitorError("monitor_policy_invalid")


class WorkerMonitor:
    """Drain bounded output while checking liveness, progress and lease renewal."""

    def __init__(self, *, clock=time.monotonic, policy=MonitorPolicy(), heartbeat: Callable[[], object] | None = None,
                 cancel_requested: Callable[[], bool] | None = None, checkpoint: Callable[[dict], None] | None = None):
        policy.validate()
        self.clock, self.policy = clock, policy
        self.heartbeat = heartbeat or (lambda: None)
        self.cancel_requested = cancel_requested or (lambda: False)
        self.checkpoint = checkpoint or (lambda _: None)

    def wait(self, process, *, timeout: float, output_limit: int) -> dict:
        if timeout <= 0 or output_limit <= 0:
            raise MonitorError("monitor_budget_invalid")
        if process.stdout is None or process.stderr is None:
            raise MonitorError("monitor_streams_missing")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        started = last_output = self.clock()
        next_heartbeat = started + self.policy.heartbeat_seconds
        timed_out = stalled = cancelled = overflow = False
        reason = "completed"
        try:
            while selector.get_map() or process.poll() is None:
                now = self.clock()
                if now >= next_heartbeat:
                    self.heartbeat()
                    next_heartbeat = now + self.policy.heartbeat_seconds
                    self.checkpoint({"elapsed_ms": int((now-started)*1000), "stdout_bytes": len(streams["stdout"]), "stderr_bytes": len(streams["stderr"]), "output_digest": _digest(bytes(streams["stdout"]+streams["stderr"]))})
                if self.cancel_requested():
                    cancelled, reason = True, "cancelled"
                    self._terminate(process)
                elif process.poll() is None and now-started >= timeout:
                    timed_out, reason = True, "timed_out"
                    self._terminate(process)
                elif process.poll() is None and now-last_output >= self.policy.output_stall_seconds:
                    stalled, reason = True, "stalled"
                    self._terminate(process)
                for key, _ in selector.select(min(.05, self.policy.heartbeat_seconds)):
                    chunk = os.read(key.fileobj.fileno(), min(4096, output_limit+1))
                    if not chunk:
                        selector.unregister(key.fileobj); key.fileobj.close(); continue
                    last_output = self.clock()
                    remaining = output_limit - sum(map(len, streams.values()))
                    if len(chunk) > remaining:
                        overflow, reason = True, "output_overflow"
                        if remaining > 0: streams[key.data].extend(chunk[:remaining])
                        self._terminate(process)
                    else:
                        streams[key.data].extend(chunk)
                if process.poll() is not None and not selector.get_map(): break
            process.wait()
        finally:
            selector.close()
        group_alive = self._group_alive(process.pid)
        if group_alive:
            self._terminate(process)
            group_alive = self._group_alive(process.pid)
        if group_alive:
            reason = "cleanup_unconfirmed"
        return {"stdout": bytes(streams["stdout"]), "stderr": bytes(streams["stderr"]),
                "returncode": process.returncode, "status": reason, "timed_out": timed_out,
                "stalled": stalled, "cancelled": cancelled, "output_overflow": overflow,
                "heartbeat_count": max(0, int((self.clock()-started)/self.policy.heartbeat_seconds)),
                "progress_observed": bool(last_output > started), "process_group_clean": not group_alive,
                "resource_observation": self._resources(process.pid)}

    def _terminate(self, process) -> None:
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        deadline = self.clock() + self.policy.terminate_grace_seconds
        while self.clock() < deadline and self._group_alive(process.pid): time.sleep(.01)
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try: process.wait(timeout=1)
        except Exception: pass

    @staticmethod
    def _group_alive(pgid: int) -> bool:
        try: os.killpg(pgid, 0); return True
        except ProcessLookupError: return False
        except PermissionError: return True

    @staticmethod
    def _resources(pid: int) -> dict:
        # Linux proc data is bounded and contains counters only, no command line.
        try:
            stat = Path(f"/proc/{pid}/stat").read_text().split()
            status = Path(f"/proc/{pid}/status").read_text().splitlines()
            rss = next((int(row.split()[1]) for row in status if row.startswith("VmRSS:")), 0)
            return {"cpu_ticks": int(stat[13])+int(stat[14]), "rss_kib": rss, "observed": True}
        except (OSError, ValueError, IndexError):
            return {"cpu_ticks": 0, "rss_kib": 0, "observed": False}


class RecoveryStore:
    """Atomic digest-bound checkpoint and bounded retry record."""

    def __init__(self, path: Path, *, max_attempts: int = 3):
        self.path, self.max_attempts = Path(path), max_attempts
        if max_attempts < 1: raise MonitorError("retry_policy_invalid")

    def checkpoint(self, binding: dict, state: dict) -> dict:
        if set(binding) != {"task_id", "task_revision", "session_id", "worktree_digest", "worker_id", "lease_id", "lease_fence"}:
            raise MonitorError("checkpoint_binding_invalid")
        if not isinstance(state, dict) or len(json.dumps(state, separators=(",", ":")).encode()) > 8192:
            raise MonitorError("checkpoint_state_invalid")
        forbidden = {"credential", "password", "secret", "token", "prompt", "transcript", "raw_output", "private_path", "host_identifier"}
        def safe(value):
            if isinstance(value, dict):
                return all(str(key).lower() not in forbidden and safe(item) for key, item in value.items())
            if isinstance(value, list): return all(safe(item) for item in value)
            return isinstance(value, (str, int, float, bool)) or value is None
        if not safe(state): raise MonitorError("checkpoint_private_state")
        record = {"schema_version": 1, "binding": binding, "state_digest": _digest(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()), "state": state}
        record["checkpoint_digest"] = _digest(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix+".tmp")
        with temp.open("w") as handle:
            json.dump(record, handle, sort_keys=True, separators=(",", ":")); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, self.path)
        return record

    def recover(self, *, binding: dict, attempts: int, old_fence: int) -> dict:
        if attempts >= self.max_attempts: raise MonitorError("retry_exhausted")
        try: record = json.loads(self.path.read_text())
        except (OSError, ValueError) as exc: raise MonitorError("checkpoint_unavailable") from exc
        saved = record.pop("checkpoint_digest", None)
        expected = _digest(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
        prior = record.get("binding", {})
        if (saved != expected or prior.get("task_id") != binding.get("task_id")
                or prior.get("task_revision") != binding.get("task_revision")
                or prior.get("session_id") != binding.get("session_id")
                or prior.get("worktree_digest") != binding.get("worktree_digest")
                or prior.get("lease_fence") != old_fence
                or binding.get("lease_fence", 0) <= old_fence
                or not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0):
            raise MonitorError("recovery_fence_invalid")
        return {"checkpoint": record, "attempt": attempts+1, "resume": True}

    def inspect(self) -> dict:
        try: record = json.loads(self.path.read_text())
        except (OSError, ValueError) as exc: raise MonitorError("checkpoint_unavailable") from exc
        saved = record.pop("checkpoint_digest", None)
        if saved != _digest(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()):
            raise MonitorError("checkpoint_digest_invalid")
        record["checkpoint_digest"] = saved
        return record

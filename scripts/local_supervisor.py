#!/usr/bin/env python3
"""AR-0083: a small, fail-closed local process supervisor.

This module is intentionally limited to repository-owned deterministic helpers.
It does not discover executables, invoke a shell, inherit the caller's
environment, or provide a provider/network adapter.  The public result is
bounded and redacted; private process details never enter the result.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover - exercised by the unsupported-host test
    resource = None


class SupervisorError(ValueError):
    """A fail-closed admission, execution, fencing, or recovery error."""


_SHELL = re.compile(r"[|;&<>`$()\n\r]")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_PRIVATE_NAME = re.compile(
    r"(?:secret|token|password|credential|api[_-]?key)", re.IGNORECASE
)
_PRIVATE_OUTPUT = re.compile(
    r"(?i)(\b(?:password|secret|token|api[_-]?key|credential)\b\s*[:=]\s*)[^\s,;]+"
    r"|(\bbearer\s+)[^\s,;]+"
)
_RUN_ID = re.compile(r"^RUN-[A-Z0-9-]{1,63}$")
_LEASE_ID = re.compile(r"^LSE-[A-Z0-9-]{1,63}$")
_MANDATORY_CONTROLS = frozenset(
    {
        "process_group",
        "rlimit_cpu",
        "rlimit_memory",
        "rlimit_file",
        "rlimit_processes",
        "output_cap",
        "worktree_cwd",
        "environment_filter",
    }
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def redact(text: str) -> str:
    """Redact values following common sensitive labels before publication."""

    return _PRIVATE_OUTPUT.sub(
        lambda match: (match.group(1) or match.group(2)) + "REDACTED", text
    )


def _bounded_int(value: object, name: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SupervisorError(f"{name} must be an integer >= {minimum}")
    return value


def _validate_redaction_values(values: Iterable[str]) -> tuple[str, ...]:
    """Validate caller-declared sensitive values without redacting ambient env."""

    if isinstance(values, (str, bytes)):
        raise SupervisorError("redaction values must be an iterable of strings")
    try:
        bounded = tuple(values)
    except TypeError as exc:
        raise SupervisorError("redaction values must be an iterable") from exc
    if len(bounded) > 32 or any(
        not isinstance(value, str) or not value or len(value) > 256
        for value in bounded
    ):
        raise SupervisorError("redaction values are unbounded or malformed")
    if len(set(bounded)) != len(bounded):
        raise SupervisorError("redaction values must be unique")
    return bounded


@dataclass(frozen=True)
class Lease:
    worker_id: str
    lease_id: str
    expires_at: float

    def validate(self) -> Lease:
        if not re.fullmatch(r"WRK-[A-Z0-9-]{1,63}", self.worker_id):
            raise SupervisorError("malformed worker identity")
        if not _LEASE_ID.fullmatch(self.lease_id):
            raise SupervisorError("malformed lease identity")
        if (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.expires_at)
        ):
            raise SupervisorError("malformed lease expiry")
        return self


@dataclass(frozen=True)
class Budget:
    timeout_ms: int = 2_000
    cpu_ms: int = 1_000
    memory_bytes: int = 256 * 1024 * 1024
    output_bytes: int = 16 * 1024
    file_bytes: int = 16 * 1024
    process_count: int = 8

    def validate(self) -> Budget:
        for name in (
            "timeout_ms",
            "cpu_ms",
            "memory_bytes",
            "output_bytes",
            "file_bytes",
            "process_count",
        ):
            _bounded_int(getattr(self, name), name)
        return self


@dataclass(frozen=True)
class SupervisorPolicy:
    worktree: Path
    allowed_executable: Path
    allowed_helpers: tuple[Path, ...]
    allowed_environment: tuple[str, ...] = (
        "LANG",
        "LC_ALL",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
    )
    network_mode: str = "offline_fixture"
    required_controls: tuple[str, ...] = (
        "process_group",
        "rlimit_cpu",
        "rlimit_memory",
        "rlimit_file",
        "rlimit_processes",
        "output_cap",
        "worktree_cwd",
        "environment_filter",
    )

    def validate(self) -> SupervisorPolicy:
        if os.name != "posix":
            raise SupervisorError(
                "unsupported host: POSIX process controls are required"
            )
        if self.network_mode != "offline_fixture":
            raise SupervisorError(
                "unsupported network control; offline fixture mode is required"
            )
        if set(self.required_controls) != _MANDATORY_CONTROLS:
            raise SupervisorError(
                "mandatory host controls cannot be omitted or replaced"
            )
        if resource is None or not hasattr(os, "killpg") or not hasattr(os, "setsid"):
            raise SupervisorError("unsupported process control")
        required_rlimits = {
            "rlimit_cpu": resource.RLIMIT_CPU,
            "rlimit_memory": resource.RLIMIT_AS,
            "rlimit_file": resource.RLIMIT_FSIZE,
            "rlimit_processes": getattr(resource, "RLIMIT_NPROC", None),
        }
        for name in self.required_controls:
            if name in required_rlimits and required_rlimits[name] is None:
                raise SupervisorError(f"unsupported host control: {name}")
        root = self.worktree.resolve(strict=True)
        executable = self.allowed_executable.resolve(strict=True)
        if not root.is_dir() or not executable.is_file():
            raise SupervisorError("worktree or executable is not a regular path")
        if not self.allowed_helpers:
            raise SupervisorError("at least one repository-owned helper is required")
        for helper in self.allowed_helpers:
            path = helper.resolve(strict=True)
            if not path.is_file() or not _inside(path, root):
                raise SupervisorError("helper is outside exact worktree")
        return self


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass
class RunHandle:
    run_id: str
    process: subprocess.Popen[bytes]
    lease: Lease
    budget: Budget
    worktree: Path
    state_file: Path
    redaction_values: tuple[str, ...] = ()
    started_at: float = field(default_factory=time.monotonic)
    cancel_requested: bool = False
    _collected: RunResult | None = None

    def cancel(self, lease: Lease, *, now: float | None = None) -> RunResult:
        if (
            lease.lease_id != self.lease.lease_id
            or lease.worker_id != self.lease.worker_id
        ):
            raise SupervisorError("stale lease cannot cancel process")
        if now is not None and now >= self.lease.expires_at:
            raise SupervisorError("expired lease cannot cancel process")
        self.cancel_requested = True
        _terminate_group(self.process)
        return self.wait()

    def wait(self, *, clock: Callable[[], float] = time.monotonic) -> RunResult:
        if self._collected is not None:
            return self._collected
        result = _collect(self, clock=clock)
        self._collected = result
        _remove_state(self.state_file)
        return result


@dataclass(frozen=True)
class RunResult:
    run_id: str
    disposition: str
    returncode: int | None
    stdout: str
    stderr: str
    output_bytes: int
    process_tree_clean: bool
    cleaned: bool
    lease_id: str

    def public(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "disposition": self.disposition,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "output_bytes": self.output_bytes,
            "process_tree_clean": self.process_tree_clean,
            "cleaned": self.cleaned,
            "lease_id": self.lease_id,
        }


class LocalSupervisor:
    """Admit, run, cancel, and recover only deterministic local helpers."""

    def __init__(
        self,
        policy: SupervisorPolicy,
        *,
        state_dir: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy.validate()
        self.clock = clock
        self.state_dir = (
            state_dir or Path(tempfile.mkdtemp(prefix="awr-0083-state-"))
        ).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._active: dict[str, RunHandle] = {}

    def launch(
        self,
        run_id: str,
        command: Iterable[str],
        *,
        lease: Lease,
        budget: Budget,
        environment: dict[str, str] | None = None,
        redaction_values: Iterable[str] = (),
        now: float | None = None,
    ) -> RunHandle:
        self.policy.validate()
        if not _RUN_ID.fullmatch(run_id) or run_id in self._active:
            raise SupervisorError("malformed or duplicated run id")
        lease.validate()
        observed = self.clock() if now is None else now
        if observed >= lease.expires_at:
            raise SupervisorError("stale lease at admission")
        budget.validate()
        argv = tuple(command)
        self._validate_command(argv)
        cwd = self.policy.worktree.resolve(strict=True)
        env = self._filter_environment(environment or {})
        explicit_redactions = _validate_redaction_values(redaction_values)
        state_file = self.state_dir / f"{run_id}.json"
        if state_file.exists():
            raise SupervisorError("run record already exists")

        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
                # Resource limits must be installed between fork and exec;
                # this supervisor is deliberately single-threaded per launch.
                preexec_fn=self._limits_preexec(budget),  # noqa: PLW1509
            )
        except (OSError, ValueError) as exc:
            raise SupervisorError("helper process admission failed") from exc
        handle = RunHandle(
            run_id, process, lease, budget, cwd, state_file, explicit_redactions
        )
        self._active[run_id] = handle
        _write_state(
            state_file,
            {
                "run_id": run_id,
                "pid": process.pid,
                "pgid": process.pid,
                "lease_id": lease.lease_id,
                "worker_id": lease.worker_id,
                "lease_expires": lease.expires_at,
                "worktree": str(cwd),
                "command_digest": digest(list(argv)),
            },
        )
        return handle

    def run(self, run_id: str, command: Iterable[str], **kwargs: object) -> RunResult:
        return self.launch(run_id, command, **kwargs).wait(clock=self.clock)

    def recover(
        self, run_id: str, *, replacement_lease: Lease, now: float | None = None
    ) -> dict[str, object]:
        """Recover an exited orphan record, fencing the old lease first."""

        if not _RUN_ID.fullmatch(run_id):
            raise SupervisorError("malformed run id")
        replacement_lease.validate()
        observed = self.clock() if now is None else now
        record_path = self.state_dir / f"{run_id}.json"
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SupervisorError("missing or malformed crash record") from exc
        if set(record) != {
            "run_id",
            "pid",
            "pgid",
            "lease_id",
            "worker_id",
            "lease_expires",
            "worktree",
            "command_digest",
        }:
            raise SupervisorError("malformed crash record")
        if record["run_id"] != run_id or observed < record["lease_expires"]:
            raise SupervisorError("old lease is not expired")
        if (
            replacement_lease.lease_id == record["lease_id"]
            or replacement_lease.worker_id == record["worker_id"]
        ):
            raise SupervisorError("recovery must fence old worker and lease")
        if _pid_exists(int(record["pid"])):
            raise SupervisorError("live orphan cannot be silently recovered")
        _remove_state(record_path)
        self._active.pop(run_id, None)
        return {
            "run_id": run_id,
            "disposition": "recovered",
            "old_lease_id": record["lease_id"],
            "replacement_lease_id": replacement_lease.lease_id,
            "worktree": record["worktree"],
            "cleaned": True,
        }

    def _validate_command(self, argv: tuple[str, ...]) -> None:
        if (
            not argv
            or len(argv) > 8
            or any(
                not isinstance(arg, str)
                or not arg
                or len(arg) > 256
                or _SHELL.search(arg)
                for arg in argv
            )
        ):
            raise SupervisorError("bounded shell-free argv required")
        executable = Path(argv[0]).resolve(strict=True)
        if executable != self.policy.allowed_executable.resolve(strict=True):
            raise SupervisorError("executable is not allowlisted")
        if len(argv) < 2:
            raise SupervisorError("repository helper argument required")
        helper = Path(argv[1]).resolve(strict=True)
        roots = tuple(path.resolve(strict=True) for path in self.policy.allowed_helpers)
        if helper not in roots or not _inside(
            helper, self.policy.worktree.resolve(strict=True)
        ):
            raise SupervisorError("helper is not repository-owned and allowlisted")
        for arg in argv[2:]:
            if arg.startswith(("/", "~")) or ".." in Path(arg).parts:
                raise SupervisorError("absolute or escaping argument rejected")

    def _filter_environment(self, requested: dict[str, str]) -> dict[str, str]:
        if not isinstance(requested, dict):
            raise SupervisorError("environment must be a mapping")
        allowed = set(self.policy.allowed_environment)
        if any(
            name not in allowed
            or not _ENV_NAME.fullmatch(name)
            or _PRIVATE_NAME.search(name)
            for name in requested
        ):
            raise SupervisorError(
                "environment contains a non-allowlisted or private name"
            )
        if any(
            not isinstance(value, str) or len(value) > 256 or _SHELL.search(value)
            for value in requested.values()
        ):
            raise SupervisorError("environment value is malformed")
        base = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
        }
        base.update(requested)
        return base

    @staticmethod
    def _limits_preexec(budget: Budget) -> Callable[[], None]:
        def apply_limits() -> None:
            assert resource is not None
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (
                    max(1, math.ceil(budget.cpu_ms / 1000)),
                    max(1, math.ceil(budget.cpu_ms / 1000)),
                ),
            )
            resource.setrlimit(
                resource.RLIMIT_AS, (budget.memory_bytes, budget.memory_bytes)
            )
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (budget.file_bytes, budget.file_bytes)
            )
            resource.setrlimit(
                resource.RLIMIT_NPROC, (budget.process_count, budget.process_count)
            )

        return apply_limits


def _write_state(path: Path, record: dict[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    os.replace(temporary, path)


def _remove_state(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _collect(handle: RunHandle, *, clock: Callable[[], float]) -> RunResult:
    process = handle.process
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    disposition = "completed"
    budget_deadline = handle.started_at + handle.budget.timeout_ms / 1000
    deadline = min(budget_deadline, handle.lease.expires_at)
    overflow = False
    while selector.get_map() or process.poll() is None:
        if clock() >= deadline and process.poll() is None:
            disposition = (
                "timed_out" if deadline == budget_deadline else "lease_expired"
            )
            _terminate_group(process)
        events = selector.select(0.02)
        for key, _ in events:
            chunk = os.read(key.fileobj.fileno(), 4096)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            remaining = max(
                0,
                handle.budget.output_bytes
                - len(buffers["stdout"])
                - len(buffers["stderr"]),
            )
            if remaining:
                buffers[key.data].extend(chunk[:remaining])
            if (
                len(chunk) > remaining
                or len(buffers["stdout"]) + len(buffers["stderr"])
                >= handle.budget.output_bytes
            ):
                overflow = True
                disposition = "output_overflow"
                _terminate_group(process)
        if process.poll() is not None and not selector.get_map():
            break
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        _terminate_group(process)
        process.wait(timeout=0.5)
    if handle.cancel_requested:
        disposition = "cancelled"
    elif overflow:
        disposition = "output_overflow"
    elif process.returncode != 0 and disposition == "completed":
        disposition = "failed"
    output_limit = handle.budget.output_bytes
    combined = bytes(buffers["stdout"] + buffers["stderr"])
    if len(combined) > output_limit:
        combined = combined[:output_limit]
    stdout = redact(bytes(buffers["stdout"][:output_limit]).decode("utf-8", "replace"))
    stderr = redact(bytes(buffers["stderr"][:output_limit]).decode("utf-8", "replace"))
    for value in handle.redaction_values:
        if value:
            stdout = stdout.replace(value, "REDACTED")
            stderr = stderr.replace(value, "REDACTED")
    return RunResult(
        handle.run_id,
        disposition,
        process.returncode,
        stdout,
        stderr,
        len(combined),
        not _pid_exists(process.pid),
        True,
        handle.lease.lease_id,
    )

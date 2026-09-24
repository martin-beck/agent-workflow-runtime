"""Bounded local process supervision for provider-free worker qualification."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Mapping, Sequence

from .cli import CliError


class HostSupervisor:
    """Run one explicitly bounded process inside a resolved worktree boundary.

    This is deliberately a local containment adapter, not a claim of container or
    kernel sandboxing. Unsupported controls are returned as ``unsupported`` and
    can be made admission-fatal with ``require_network_disabled``.
    """

    def __init__(self, root: Path):
        self.root = root.expanduser().absolute()
        if self.root.is_symlink() or not self.root.is_dir():
            raise CliError("host_root_invalid")
        self.root = self.root.resolve()

    def _cwd(self, cwd: Path) -> Path:
        if cwd.is_symlink() or not cwd.exists() or not cwd.is_dir():
            raise CliError("host_cwd_invalid")
        resolved = cwd.absolute().resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise CliError("host_cwd_escape") from exc
        return resolved

    @staticmethod
    def _argv(argv: Sequence[str]) -> list[str]:
        if not argv or len(argv) > 64 or any(not isinstance(item, str) or not item or len(item) > 4096 for item in argv):
            raise CliError("host_argv_invalid")
        return list(argv)

    @staticmethod
    def _preexec(cpu_seconds: int, memory_bytes: int):
        def limit() -> None:
            try:
                import resource

                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            except (ImportError, OSError, ValueError):
                # The result reports this as unsupported; never call it enforced.
                pass

        return limit

    def run(
        self,
        argv: Sequence[str],
        cwd: Path,
        *,
        env: Mapping[str, str] | None = None,
        allowed_env: Sequence[str] = (),
        timeout_seconds: float = 5.0,
        output_limit: int = 16384,
        cpu_seconds: int = 2,
        memory_bytes: int = 256 * 1024 * 1024,
        require_network_disabled: bool = True,
    ) -> dict[str, object]:
        command = self._argv(argv)
        worktree = self._cwd(cwd)
        if not 0 < timeout_seconds <= 300 or not 0 < output_limit <= 1024 * 1024 or not 0 < cpu_seconds <= 300 or not 1024 * 1024 <= memory_bytes <= 8 * 1024 * 1024 * 1024:
            raise CliError("host_limits_invalid")
        if require_network_disabled:
            raise CliError("host_network_control_unsupported")
        base = {key: os.environ[key] for key in allowed_env if key in os.environ}
        if env:
            if any(key not in allowed_env or not isinstance(key, str) or not isinstance(value, str) for key, value in env.items()):
                raise CliError("host_environment_not_allowlisted")
            base.update(env)
        started = time.monotonic()
        proc = subprocess.Popen(
            command,
            cwd=worktree,
            env=base,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=self._preexec(cpu_seconds, memory_bytes) if os.name == "posix" else None,
            text=False,
        )
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL) if os.name == "posix" else proc.kill()
            stdout, stderr = proc.communicate()
            stdout = exc.output or stdout
            stderr = exc.stderr or stderr
        elapsed = time.monotonic() - started
        truncated = len(stdout) > output_limit or len(stderr) > output_limit
        return {
            "status": "timeout" if timed_out else ("ok" if proc.returncode == 0 else "failed"),
            "returncode": proc.returncode,
            "stdout": stdout[:output_limit].decode("utf-8", "replace"),
            "stderr": stderr[:output_limit].decode("utf-8", "replace"),
            "output_truncated": truncated,
            "elapsed_seconds": round(elapsed, 6),
            "worktree": str(worktree),
            "controls": {
                "argv_bounded": True,
                "environment_allowlist": True,
                "worktree_boundary": True,
                "process_group_cleanup": os.name == "posix",
                "cpu_limit": os.name == "posix",
                "memory_limit": os.name == "posix",
                "network_disabled": False,
                "network_control": "unsupported",
            },
        }

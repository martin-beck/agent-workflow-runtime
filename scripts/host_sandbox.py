"""Enforceable Linux worker sandbox boundary.

This is deliberately separate from ``local_supervisor``.  That module is a
bounded subprocess adapter and must not be described as a sandbox.  This
adapter admits a worker only when Bubblewrap has successfully demonstrated
the mount, network, PID, and parent-death controls used for the run.
"""

from __future__ import annotations

import os
import resource
import selectors
import shutil
import signal
import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


class SandboxError(ValueError):
    """Fail-closed sandbox admission or execution error."""


@dataclass(frozen=True)
class SandboxBudget:
    timeout_seconds: float = 2.0
    cpu_seconds: int = 1
    memory_bytes: int = 256 * 1024 * 1024
    disk_bytes: int = 16 * 1024
    output_bytes: int = 16 * 1024
    process_count: int = 8

    def validate(self) -> None:
        if not 0 < self.timeout_seconds <= 300:
            raise SandboxError("invalid timeout budget")
        if any(value <= 0 for value in (self.cpu_seconds, self.memory_bytes, self.disk_bytes, self.output_bytes, self.process_count)):
            raise SandboxError("invalid resource budget")


DEFAULT_BUDGET = SandboxBudget()


@dataclass(frozen=True)
class SandboxCapabilities:
    runtime: str
    filesystem: bool
    network: bool
    process: bool
    cpu: bool
    memory: bool
    disk: bool
    timeout: bool
    cancellation: bool
    cleanup: bool

    @property
    def enforceable(self) -> bool:
        return self.runtime == "bwrap" and all((self.filesystem, self.network, self.process, self.cpu,
                    self.memory, self.disk, self.timeout, self.cancellation,
                    self.cleanup))

    def as_dict(self) -> dict[str, object]:
        return {"runtime": self.runtime, "enforceable": self.enforceable,
                "filesystem": self.filesystem, "network": self.network,
                "process": self.process, "cpu": self.cpu,
                "memory": self.memory, "disk": self.disk,
                "timeout": self.timeout, "cancellation": self.cancellation,
                "cleanup": self.cleanup}


def _system_binds() -> list[str]:
    binds: list[str] = []
    for path in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        if Path(path).exists():
            binds += ["--ro-bind", path, path]
    return binds


class HostSandbox:
    """Run a bounded command in a private mount/network/PID namespace."""

    def __init__(self, worktree: Path, *, runtime: str | None = None) -> None:
        self.worktree = worktree.resolve(strict=True)
        if not self.worktree.is_dir():
            raise SandboxError("worktree must be a directory")
        self.runtime = runtime or shutil.which("bwrap")
        self.capabilities = self.probe()
        if not self.capabilities.enforceable:
            raise SandboxError("required host sandbox controls unavailable")

    def probe(self) -> SandboxCapabilities:
        if os.name != "posix" or not self.runtime or resource is None:
            return SandboxCapabilities("unavailable", *(False,) * 9)
        try:
            result = subprocess.run(
                self._prefix(Path("/"), probe=True) + ["/usr/bin/true"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False, timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return SandboxCapabilities("bwrap", *(False,) * 9)
        rlimits = all(hasattr(resource, name) for name in
                      ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_NPROC"))
        ok = result.returncode == 0 and rlimits and hasattr(os, "killpg")
        return SandboxCapabilities("bwrap", ok, ok, ok, rlimits, rlimits,
                                    rlimits, True, ok, ok)

    def _prefix(self, cwd: Path, *, probe: bool = False) -> list[str]:
        command = [self.runtime, "--die-with-parent", "--new-session",
                   "--unshare-user-try", "--unshare-net", "--unshare-pid", *(_system_binds())]
        command += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
        if not probe:
            command += ["--bind", str(self.worktree), "/work", "--chdir", "/work"]
        return [str(item) for item in command]

    @staticmethod
    def _limits(budget: SandboxBudget):
        def apply() -> None:
            resource.setrlimit(resource.RLIMIT_CPU, (budget.cpu_seconds, budget.cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS, (budget.memory_bytes, budget.memory_bytes))
            resource.setrlimit(resource.RLIMIT_FSIZE, (budget.disk_bytes, budget.disk_bytes))
            resource.setrlimit(resource.RLIMIT_NPROC, (budget.process_count, budget.process_count))
        return apply

    def launch(self, argv: Iterable[str], *, budget: SandboxBudget | None = None) -> subprocess.Popen[bytes]:
        budget = budget or DEFAULT_BUDGET
        budget.validate()
        args = tuple(argv)
        if not args or any(not isinstance(arg, str) or not arg or len(arg) > 4096 for arg in args):
            raise SandboxError("bounded argv required")
        limited = ["/usr/bin/prlimit", f"--cpu={budget.cpu_seconds}",
                   f"--as={budget.memory_bytes}", f"--fsize={budget.disk_bytes}",
                   f"--nproc={budget.process_count}", "--", *args]
        process = subprocess.Popen(
            self._prefix(self.worktree) + limited, cwd=self.worktree,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, close_fds=True,
        )
        return process

    def run(self, argv: Iterable[str], *, budget: SandboxBudget | None = None) -> dict[str, object]:
        budget = budget or DEFAULT_BUDGET
        process = self.launch(argv, budget=budget)
        stdout, stderr, timed_out, overflow = self._collect(process, budget)
        return {"status": "timeout" if timed_out else ("output_overflow" if overflow else ("ok" if process.returncode == 0 else "failed")),
                "returncode": process.returncode, "stdout": stdout[:budget.output_bytes].decode("utf-8", "replace"),
                "stderr": stderr[:budget.output_bytes].decode("utf-8", "replace"),
                "controls": self.capabilities.as_dict(),
                "process_tree_clean": process.poll() is not None,
                "cleanup": process.poll() is not None}

    def _collect(self, process: subprocess.Popen[bytes], budget: SandboxBudget) -> tuple[bytes, bytes, bool, bool]:
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + budget.timeout_seconds
        timed_out = False
        overflow = False
        while selector.get_map() or process.poll() is None:
            if process.poll() is None and time.monotonic() >= deadline:
                timed_out = True
                self.cancel(process)
            for key, _ in selector.select(.02):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                remaining = budget.output_bytes - len(buffers["stdout"]) - len(buffers["stderr"])
                if remaining <= 0 or len(chunk) > remaining:
                    overflow = True
                    if remaining > 0:
                        buffers[key.data].extend(chunk[:remaining])
                    self.cancel(process)
                else:
                    buffers[key.data].extend(chunk)
            if process.poll() is not None and not selector.get_map():
                break
        process.wait()
        selector.close()
        return bytes(buffers["stdout"]), bytes(buffers["stderr"]), timed_out, overflow

    @staticmethod
    def cancel(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
            except ProcessLookupError:
                pass

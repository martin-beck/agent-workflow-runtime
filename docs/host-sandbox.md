# Host sandbox profile

`HostSandbox` in `scripts/host_sandbox.py` is the only runtime path that may
claim an enforceable host sandbox. It is a Linux/Bubblewrap adapter, separate
from `awr host-run` and `scripts.local_supervisor`: those subprocess paths are
bounded adapters, not sandboxes.

Admission probes Bubblewrap before a worker is started. A missing runtime,
failed namespace probe, missing POSIX limits, or unsupported control rejects
admission. The profile gives the worker a private mount namespace with only
the worktree writable, a private network namespace, a private PID namespace,
and parent-death cleanup. `prlimit` applies CPU, address-space, per-file disk,
and process-count budgets to the worker. The supervisor independently bounds
wall-clock time, output, cancellation, process-group termination, and cleanup.

The disk budget is an enforced per-file `RLIMIT_FSIZE` limit; a host-wide disk
quota is not claimed. System paths are visible read-only only as runtime
dependencies. Symlink traversal cannot create writable access outside the
worktree. All controls are reported as capabilities, but only a positive
Bubblewrap probe makes the profile enforceable.

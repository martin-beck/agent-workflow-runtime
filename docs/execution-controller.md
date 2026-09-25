<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# AR-0131 execution controller

`scripts.execution_controller.ExecutionController` is the first executable
runtime path. It accepts one exact Coordinator task revision, project and
worktree binding, registry revision/profile, authority admission observation,
and live scheduler lease. Every binding is checked before `HostSandbox` is
constructed; missing, stale, crossed, unsupported, or replayed inputs fail
closed without starting a process.

The only executable profile in this boundary is a registry profile whose
command profile is `deterministic-agent` and whose sandbox requirement is true.
The controller starts one fixed local fake using an argv array, an explicit
allow-listed environment, stdin/stdout/stderr pipes, a new process group,
Bubblewrap namespaces, `prlimit` budgets, and the session/task bindings.
Provider, credential/key, and model configuration are not read, copied,
provisioned, or mutated.

Each session writes one atomically replaced JSON evidence file. The `spawn`
record contains exact identity/revision/lease/profile bindings, argv and
environment-name digests, stdio/process-group/resource controls, and the
provider/configuration non-claims. The `terminal` record contains bounded
output digests and sizes, exit disposition, and cleanup evidence. Evidence is
not a Coordinator state mutation; Coordinator remains authoritative for task
and lease state.

Run the focused check with:

```text
python3 -m unittest tests.test_execution_controller tests.test_host_sandbox -v
```

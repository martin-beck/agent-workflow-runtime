<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# AR-0131 execution controller

## AR-0132 interactive session protocol

`scripts/interactive_session.py` layers a bounded turn and event protocol over
an already admitted session binding and its live lease fence. Inputs carry the
session, task revision, lease ID and fence, correlation ID, prompt, and absolute
deadline. Frames are limited to 4096 bytes; prompts are limited to 2048 bytes;
each turn has bounded queued events and each session has at most 64 recorded
events. Deadlines cannot extend beyond the lease. Output is accepted only
while a turn is pending, from stdout or stderr, and is normalized to assistant,
tool, or status events followed by an explicit end-turn and terminal event.
Sequence numbers and canonical SHA-256 digests make record/replay deterministic.
Credential-like labels and bearer values are redacted before events are kept.

The deterministic `fake-alpha` protocol uses `{ "type": ..., "data": ... }`;
`fake-beta` uses `{ "event": ..., "payload": ... }`. Their native field names
are erased by normalization. The implementation receives native frames from
the admitted session transport; it does not configure or inspect a provider,
key, or model. `specifications/interactive-agent-session-v1.json` records the
wire bounds and rejection contract. Run the focused offline checks with
`python3 -m unittest tests.test_interactive_session -v`.

`scripts.execution_controller.ExecutionController` is the first executable
runtime path. It accepts one exact Coordinator task revision, project and
worktree binding, registry revision/profile, and authority admission
observation. It reads the task and requests its claim and fenced lease through
the required Coordinator client before process start. The controller accepts
no caller-provided lease. Missing, stale, crossed,
unsupported, or replayed bindings fail closed without starting a process.

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
output digests and sizes, exit disposition, and cleanup evidence. Each evidence
record is paired with Coordinator session events, a heartbeat, and terminal
reconciliation. `scripts/durable_coordinator.py` provides the restartable,
atomic file-backed fake used in CI. It enforces revision CAS, fenced lease
expiry, exact-operation idempotency, and ambiguous-write recovery by retrying
the same operation ID and payload. This fake is not a hosted Coordinator
implementation or live-state verification. Provider configuration remains
assumed and uninspected; provider execution is not performed.

Run the focused check with:

```text
python3 -m unittest tests.test_execution_controller tests.test_host_sandbox -v
```
# AR-0134 worker monitoring and recovery

`scripts/worker_monitor.py` monitors the spawned session while draining both
output streams. It renews the current Coordinator lease on a bounded interval,
records digest-only progress checkpoints, samples Linux CPU and resident-memory
counters, and detects process exit, deadline expiry, output stalls, overflow,
and cancellation. A cancel request fences further interactive input and output;
the terminal cancellation acknowledgement is emitted only after the process
group is confirmed clean. A late or duplicate event remains rejected by the
lease and operation bindings.

`RecoveryStore` atomically records a canonical checkpoint bound to task,
revision, session, worktree digest, worker, lease, and fence. Recovery verifies
the stored digest and requires a strictly newer fence and an available attempt
under the bounded retry limit. The controller's Coordinator client remains the
authority for acquiring that new lease; the store cannot mint leases or mark a
task terminal. See `specifications/worker-monitor-recovery-v1.json`.

The hostile local tests use deterministic worker processes to cover a hanging
worker, a stalled output stream, a worker with a descendant, cancellation,
checkpoint restart, retry exhaustion, and stale fencing. These tests do not
inspect provider configuration, run a provider, or establish hosted CI or
production host containment.

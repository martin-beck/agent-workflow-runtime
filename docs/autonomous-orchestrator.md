# Durable autonomous workflow orchestration

`scripts/autonomous_orchestrator.py` composes the Coordinator-shaped local
durable state, dependency scheduler, supervised agent session, and worker gate
loop. The versioned contract is
`specifications/autonomous-orchestrator-v1.json`.

The input is a strict JSON graph. It binds a project revision, task revisions,
dependency edges, worktree keys and digests, a deterministic fake profile, and
digest-only action requests. Its approval object must identify a Coordinator
decision and bind the canonical graph digest (computed with the `approval`
member omitted). Dependencies must form an acyclic graph. Only dependency-ready
tasks are selected, and concurrency is the lower of the graph and operator
limits (both at most eight).

Each dispatched task gets a separate atomic, restartable Coordinator fake
state file. `ExecutionController` requests the claim and fenced lease, starts
the deterministic `autonomous-mock` profile inside `HostSandbox`, and uses
`WorkerMonitor` for output bounds, lease heartbeat, process cleanup, and
checkpoints. Its bounded fake-alpha frames are consumed and replay-checked by
`InteractiveSession`; only normalized event digests are appended under the
same Coordinator lease. AWQ, AWG, and UI are consumed in that order through
the existing worker control loop. A failed or cancelled gate reconciles as
failed or blocked; only three bound approved outcomes permit `done`.

The run journal is an atomic, fsynced, hash-linked event log. On restart,
`resume` verifies the graph digest, journal chain, and derived status projection.
An unfinished Coordinator lease is recovered only after its recorded expiry
and only with a valid digest-bound checkpoint; recovery obtains a fresh fence
and writes fence-specific evidence. While a lease remains active, the run
defers work. A crash after terminal reconciliation is resolved from the
Coordinator terminal state plus the complete gate journal. Terminal journal
entries cannot be replayed into another outcome. The operator API accepts no
executable or arbitrary worker command.

Example operator commands from a source checkout:

```text
awr workflow start --graph approved-graph.json --state-dir .awr/run \
  --worktree project=./project --max-parallel 2
awr workflow status --graph approved-graph.json --state-dir .awr/run
awr workflow resume --graph approved-graph.json --state-dir .awr/run \
  --worktree project=./project --max-parallel 2
```

The graph currently admits `generic-mock-agent`, mapped to the registry's
sandbox-required deterministic mock profile. Coordinator, AWQ, AWG, and UI
decisions in this mode are durable local fakes. Provider credentials and model
configuration are not read or inspected; no network or hosted check is
performed. This qualifies the local orchestration boundary, not a live
provider, hosted authority, remote execution, or production host. No claim is
made that these deterministic gate results represent real authority decisions.

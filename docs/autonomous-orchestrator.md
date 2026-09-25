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

## Run operations and board evidence

`awr run-ops` records and projects one already-admitted run/task binding. It is
the operator journal around the workflow runtime; `awr workflow start` remains
the command that starts the approved local orchestrator. The binding file is a
privacy-safe projection of the exact graph, Coordinator task revision, worker,
session, and current lease. It contains only identifiers, revisions, lease
expiry, limits, and digests. Mutations repeat `--run-id`, expected board
revision, lease ID, and fence; the journal rejects mismatches and expired
leases. Recovery additionally needs a digest-bound checkpoint and a new worker
and lease fence.

```text
awr run-ops start --state-file .awr/run/board.json --binding run-binding.json \
  --operation-id OP-START-1
awr run-ops status --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1
awr run-ops follow --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1 \
  --after-sequence 3
awr run-ops interrupt --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1 \
  --operation-id OP-INT-1 --expected-revision 4 --lease-id LSE-EXAMPLE-1 \
  --lease-fence 1
awr run-ops resume --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1 \
  --operation-id OP-RESUME-1 --expected-revision 6 --lease-id LSE-EXAMPLE-1 \
  --lease-fence 1 --observation resume-checkpoint.json
awr run-ops cancel --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1 \
  --operation-id OP-CANCEL-1 --expected-revision 7 --lease-id LSE-EXAMPLE-1 \
  --lease-fence 1
awr run-ops diagnose --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1
awr run-ops export-evidence --state-file .awr/run/board.json --run-id RUN-EXAMPLE-1
```

`interrupt`, `resume`, and `cancel` append requests, not claims that the action
occurred. A subsequent bounded observation must confirm the result. The board
shows the current worker/session/lease mapping, Coordinator and gate outcomes,
failure code, checkpoint digest, accounting, artifact digests, and journal
head. Export validation rechecks the event chain, accounting conservation,
artifact references, redaction policy, and evidence digest. Unknown outcomes
stay unknown; accepted requires Coordinator `done` and explicit AWQ, AWG, and
UI outcomes. Provider execution is not performed, credentials are not
inspected, and remote verification remains unverified.

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

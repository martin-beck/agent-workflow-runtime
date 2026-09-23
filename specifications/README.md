<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Runtime specifications

Every design or conceptual decision in this project must have a versioned,
machine-readable specification under this directory before implementation or
oracle selection. Each specification must have an autonomous positive and
negative checker, an explicit limitation section, and a result bound to the
exact task revision and specification digest.

Specifications are contract evidence, not implementation-refinement proofs.
They must not contain credentials, private paths, prompts, transcripts, host
identifiers, or unbounded command output.

## AR-0001 admission checker

`runtime-charter-v1.json` is the v1 runtime charter, authority matrix, and
specification-before-implementation admission rule. Its canonical UTF-8 JSON
bytes are identified by `sha256:` plus a lowercase SHA-256 digest. An admission
envelope must bind that digest and the current Coordinator task revision, and
must contain unique evidence identifiers and digests.

Run the checker from the repository root with Python's standard library:

```text
python3 scripts/check_admission.py \
  --spec specifications/runtime-charter-v1.json \
  --admission specifications/fixtures/admission-ar0001-v1.json \
  --expected-revision 5
```

The checker is offline and fail-closed. It validates shape, authority-domain
ownership, revision/digest binding, evidence replay, and prohibited private
data in the envelope. It does not verify Coordinator or AWQ state, prove
implementation refinement, enforce process isolation, or establish hosted
CI, provider, GitHub, or remote runtime success. Those authorities remain
external to this repository and must be evidenced separately.

## AR-0002 normalized session-event protocol

`session-event-protocol-v1.json` defines the provider-neutral envelope and
fail-closed trace rules. `scripts/check_session_events.py` checks the exact
Coordinator task revision, canonical event digests, event/evidence uniqueness,
parent-linked ordering, session/worktree/adapter binding, terminal fencing,
compatibility, and privacy-safe shape. The deterministic trace fixture is
`fixtures/session-trace-ar0002-v1.json`.

Run it offline from the repository root:

```text
python3 scripts/check_session_events.py \
  --trace specifications/fixtures/session-trace-ar0002-v1.json \
  --expected-revision 5
```

This checker validates supplied trace consistency only. It does not consult or
prove Coordinator state, AWQ/AWG/UI decisions, evidence truth, signing,
process isolation, provider behavior, hosted CI, or remote runtime success.

## AR-0003 agent adapter lifecycle

`agent-adapter-lifecycle-v1.json` defines the provider-neutral adapter
capability report and the fail-closed lifecycle from discovery through start,
bounded digest-referenced interaction, termination, or failure. The offline
reference implementation is `scripts/agent_adapter.py`; its checker validates
the deterministic trace fixture with no provider or process connection:

```text
python3 scripts/check_agent_adapter.py \
  --spec specifications/agent-adapter-lifecycle-v1.json \
  --trace specifications/fixtures/adapter-trace-ar0003-v1.json \
  --expected-revision 5
```

This contract does not launch agents, authenticate providers, or provide
resume, supervision, resource containment, durable journaling, or recovery.
Those boundaries remain deferred to the follow-up ARs named by the
specification.

`fixtures/adapter-evidence-ar0003-v1.json` records the exact revision,
specification and trace digests, evidence identifiers, and offline tool
versions. It does not claim provider or remote execution.

## AR-0004 project, worktree, and capability boundary

`worktree-capability-v1.json` binds an admitted session to one Coordinator task
revision, project revision, exclusive worktree identity, bounded tool grant,
and explicit authority observations. `scripts/check_boundary.py` accepts only
the documented `read`, `edit`, and `test` tools, fences lifecycle transitions,
and rejects stale, cross-boundary, replayed, privacy-bearing, and authority-
mutating input.

Run the deterministic checker offline:

```text
python3 scripts/check_boundary.py \
  --spec specifications/worktree-capability-v1.json \
  --record specifications/fixtures/boundary-ar0004-v1.json \
  --expected-revision 5 \
  --expected-project agent-workflow-runtime \
  --expected-worktree agent-workflow-runtime-0004
```

The fixture records only the task revision, specification/evidence digests,
checker version, and safe identifiers. The checker does not inspect or create
a worktree, execute a tool, consult Coordinator/AWQ/AWG/UI, or establish
filesystem isolation; those claims require later integration work (AR-0019).

## AR-0005 supervisor admission and lifecycle

`supervisor-lifecycle-v1.json` defines task/worktree admission, fenced leases
and heartbeats, cancellation, worker handoff, stale-worker recovery, and
terminal lifecycle transitions. `scripts/check_supervisor.py` and the
standard-library `SupervisorState` model are deterministic and fail closed.

```text
python3 scripts/check_supervisor.py \
  --spec specifications/supervisor-lifecycle-v1.json \
  --trace specifications/fixtures/supervisor-trace-ar0005-v1.json \
  --expected-revision 5
```

The model observes integer times only. It does not launch or stop workers,
renew a real Coordinator lease, persist state, or prove provider, filesystem,
hosted-CI, remote, or runtime success. Handoff and recovery replace the worker
and lease before resume; old worker actions are rejected.

## AR-0006 resource and termination boundary

`resource-boundary-v1.json` defines positive integer budgets for CPU, memory,
disk, network, process-tree size/depth, and wall-clock timeout. It also requires
a complete process-tree observation and an acknowledged cancellation whenever
cancellation is requested. `scripts/resource_boundary.py` evaluates only
normalized deterministic observations; `scripts/check_resource_boundary.py`
validates the closed, revision-bound evidence envelope and recomputes the
result. Missing or unknown fields, invalid types, budget excess, timeout,
incomplete process-tree evidence, and unacknowledged cancellation fail closed.

```text
python3 scripts/check_resource_boundary.py \
  --spec specifications/resource-boundary-v1.json \
  --trace specifications/fixtures/resource-trace-ar0006-v1.json \
  --expected-revision 5
```

This is an offline standard-library model. It does not set OS limits, inspect
or stop processes, measure a host, send network traffic, or establish provider,
remote, hosted-CI, or real runtime enforcement.

## AR-0007 checkpoint, interruption, and crash recovery

`checkpoint-recovery-v1.json` defines immutable, revision-bound durable
checkpoints; exact idempotent retries; interruption acknowledgement; host or
agent failure; and restart through a newer worker/lease and verified replay.
`scripts/checkpoint_recovery.py` is the standard-library reference model and
`scripts/check_checkpoint_recovery.py` is its fail-closed checker.

Run the deterministic trace check offline:

```text
python3 scripts/check_checkpoint_recovery.py \
  --spec specifications/checkpoint-recovery-v1.json \
  --trace specifications/fixtures/checkpoint-recovery-ar0007-v1.json \
  --expected-revision 5
```

The checker rejects stale revisions, duplicate or changed operations, replayed
events, cross-worker recovery, unverified checkpoint replay, invalid lifecycle
transitions, unknown fields, and private evidence. It validates supplied
observations only; it does not perform durable I/O, detect a real crash, or
claim Coordinator, provider, host, remote, or runtime success.

## AR-0008 privacy-safe journal and provenance

`privacy-safe-journal-v1.json` defines the versioned redacted journal,
canonical record digests, hash-chain predecessor, idempotent operation replay,
bounded retention anchor, interruption fence, and payload-free public evidence
projection. `scripts/privacy_safe_journal.py` is the offline standard-library
reference model; `scripts/check_privacy_safe_journal.py` validates the exact
revision-5 fixture and its specification/journal digests:

```text
python3 scripts/check_privacy_safe_journal.py \
  --spec specifications/privacy-safe-journal-v1.json \
  --journal specifications/fixtures/journal-ar0008-v1.json \
  --evidence specifications/fixtures/journal-evidence-ar0008-v1.json \
  --expected-revision 5
```

The model does not provide fsync, locking, signatures, crash durability, or
general personal-data classification. It performs no network, provider,
Coordinator, AWQ, AWG, UI, Git, or LLM operation.

## AR-0015 provider-neutral Codex-style adapter

`codex-style-adapter-v1.json` defines the revision-5-bound, turn-oriented
adapter contract. It uses capability discovery and digest-only turn
references; provider commands, prompts, transcripts, credentials, and raw
output are outside the contract. The offline model is
`scripts/codex_adapter.py`, and its fail-closed replay checker is
`scripts/check_codex_adapter.py`:

```text
python3 scripts/check_codex_adapter.py \\
  --spec specifications/codex-style-adapter-v1.json \\
  --trace specifications/fixtures/codex-replay-ar0015-v1.json \\
  --expected-revision 5
```

The evidence fixture binds the canonical specification and trace digests.
These files do not launch Codex, any provider, a process, network, or LLM,
and do not prove provider availability or runtime success.

## AR-0009 AWQ evidence bridge

`awq-evidence-bridge-v1.json` defines the smallest versioned projection from
runtime observations to AWQ evidence. The offline model is
`scripts/awq_evidence_bridge.py`; its checker rejects stale or cross-worktree
bindings, replayed digests, privacy-bearing fields, unknown fields, and any
attempt to encode a quality decision. `quality_status` is deliberately
`not_decided`; AWQ must independently apply its requirements and acceptance
policy. No AWQ, Coordinator, provider, network, or runtime connection is made.

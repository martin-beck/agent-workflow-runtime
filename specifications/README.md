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

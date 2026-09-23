<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Architecture

```text
agent CLI/provider
        │
   AgentAdapter
        │ normalized events/actions
        ▼
 AWR Supervisor ── CapabilityBroker ── Worktree/Resource Boundary
        │
   EvidenceBridge ── PublicationBridge
        │                 │
        ▼                 ▼
       AWQ       Git/PR/CI observations
        │
   OracleBridge ── AWG/UI
        │
        ▼
 Coordinator task/revision/state authority
```

## Authority boundaries

The runtime is an enforcer and translator, not a fourth policy authority.
Coordinator decides whether a task may transition. AWQ decides whether
required evidence satisfies quality policy. AWG decides whether an oracle
interaction is required and records the oracle's decision. AWR may stop,
checkpoint, or request clarification, but cannot manufacture an approval,
quality result, or task completion.

## Required components

1. `AgentAdapter`: launch, event streaming, interruption, resume, and close for
   one agent implementation.
2. `Supervisor`: leases, deadlines, process lifecycle, resource limits,
   checkpoints, retries, and crash recovery.
3. `CapabilityBroker`: task-scoped, time-bounded capabilities for reading,
   editing, testing, publishing, and state mutation.
4. `EvidenceBridge`: bounded, digest-bound projections into AWQ evidence.
5. `OracleBridge`: revision-bound AWG packets, responses, and safe resume.
6. `PublicationBridge`: exact-head review, CI observation, merge, release,
   reconciliation, and live-doctor evidence.
7. `ReplayHarness`: deterministic positive and hostile session traces.

All components must preserve the task ID, task revision, worktree identity,
session ID, adapter identity, and evidence digests across boundaries.

## AR-0005 supervisor boundary

Supervisor admission is bound to the Coordinator task revision, project and
exclusive worktree identity, session, worker, and lease. Every action is fenced
by the current worker and lease. A heartbeat must advance both observation time
and expiry; cancellation is an explicit cancelling/acknowledged transition.
Handoff and stale recovery replace the worker and lease before resume, fencing
the old worker. Expiry is fail-closed: the old worker cannot heartbeat or act,
and recovery is allowed only after expiry.

The offline reference model and checker are in `scripts/supervisor.py` and
`scripts/check_supervisor.py`. They validate supplied evidence only and do not
claim Coordinator, process, provider, or remote execution effects. Production
integration remains the scope of AR-0018.

## AR-0004 execution boundary

Before a session is active, the runtime boundary must carry the exact
Coordinator task revision, project revision, and exclusive worktree key and
digest. Its capability grant is limited to versioned `read`, `edit`, and
`test` tools. Network, provider, credential, publication, merge, durable-state
mutation, and authority-decision operations are denied by default.

Coordinator, AWQ, AWG, and UI values are observations or inputs to enforcement;
they are not runtime approvals. A runtime session may start, interrupt, resume
with the identical binding, or close, but cannot manufacture a claim, quality
acceptance, oracle decision, merge, publication, or completion. The AR-0004
offline checker validates this projection only; it does not prove filesystem
isolation or execute tools.

## AR-0006 resource and termination boundary

The resource boundary is a versioned, fail-closed contract for bounded CPU,
memory, disk, network, process-tree, timeout, and cancellation observations.
The offline reference model accepts only complete normalized observations and
rejects any exceeded budget, incomplete process-tree observation, timeout, or
unacknowledged cancellation. It is evidence evaluation, not host enforcement;
OS-specific containment and live measurement remain a later integration scope.

## AR-0017 provider-neutral OpenDesk-style adapter

The AR-0017 adapter contract projects a bounded capability set and accepts
only digest-referenced requests. It deliberately models an OpenDesk-style
interface without naming or launching OpenDesk or another provider. Supported
capabilities produce normalized accepted outcomes with `execute: false`;
known but unadvertised capabilities produce the explicit
`unsupported_capability` disposition and preserve lifecycle state. Unknown
capabilities, stale revisions, privacy-bearing values, and invalid transitions
are rejected fail-closed.

`scripts/opendesk_adapter.py` and `scripts/check_opendesk_adapter.py` are
offline reference/model checks. They prove only the supplied contract shape
and deterministic transitions. They do not prove provider availability,
authorization, transport, model behavior, tool or file execution, or runtime
success.

## AR-0016 provider-neutral OpenCode-style mapping

The AR-0016 adapter is an offline translation boundary, not an OpenCode
client. Its versioned mapping converts bounded native event kinds into the
normalized session vocabulary while preserving the exact Coordinator revision,
session, worktree, and adapter identity. Native content is represented only by
digests and bounded metadata. The replay checker fails closed on unknown kinds
or fields, stale or crossed bindings, privacy-bearing values, changed
normalized output, and duplicate native events. A passing replay is structural
evidence only.

## AR-0015 provider-neutral Codex-style adapter

AR-0015 adds a turn-oriented adapter contract for Codex-style interaction
without embedding a Codex or provider implementation. Capability discovery is
bounded metadata; turns carry digest references only. The reference model and
replay checker are offline state machines and cannot establish provider,
process, network, Coordinator, or runtime success.

## AR-0009 AWQ evidence bridge

The EvidenceBridge projects bounded, digest-referenced runtime observations
into an AWQ-shaped envelope while preserving the exact Coordinator task
revision, project revision, worktree, and session. Its `quality_status` is
always `not_decided`: observation results are inputs for AWQ review, never AWQ
acceptance. The standard-library model and checker are
`scripts/awq_evidence_bridge.py` and `scripts/check_awq_evidence_bridge.py`.

## AR-0012 provider-neutral Git/publication bridge

The publication bridge accepts a bounded observation envelope for one branch,
commit, review, merge, and publication state. It binds the exact branch head
through every stage and requires positive valid-signature and signed-DCO
observations. Evidence is canonical JSON with SHA-256 digests; unknown fields,
stale revision-3 bindings, replay, privacy-bearing values, wrong heads, and
unsigned evidence fail closed. Merge and publication must remain
`not_performed`, so this AR performs no provider, Git, review-system, merge, or
remote publication operation. The model and checker validate supplied evidence
only and do not verify cryptographic signatures or DCO trailers themselves.

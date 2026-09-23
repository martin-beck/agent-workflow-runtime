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


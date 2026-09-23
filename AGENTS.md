<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Contributor instructions

Agent Workflow Runtime (AWR) is the execution and integration layer for the
Agent Workflow family. Read `README.md`, `docs/ARCHITECTURE.md`, and
`docs/PROTOCOL.md` before changing runtime behavior.

Coordinator remains authoritative for task identity, claims, dependencies,
revisions, leases, and durable state. Agent Workflow Quality (AWQ) remains
authoritative for requirements, gates, and evidence. Agent Workflow Guidance
(AWG) remains authoritative for oracle escalation, decisions, and reusable
guidance. AWR must translate and enforce these contracts; it must not duplicate
their authority or schemas.

Every adapter and supervisor transition requires positive and hostile tests.
Commands must use bounded argument arrays, remain privacy-safe, and preserve
exact task revisions and worktree identity. Do not add credentials, telemetry,
private paths, prompts, transcripts, host identifiers, unbounded output,
floating versions, or network-required startup.

Use the project-bound Git-backed Coordinator state repository for every
state-changing product, Git, review, publication, and coordination operation.
Run AWQ's applicable offline checks and record exact evidence before release.
Commits must be SSH-signed and contain a matching DCO `Signed-off-by` trailer.


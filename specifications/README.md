<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Runtime specifications

Every design or conceptual decision in this project must have a versioned,
machine-readable specification under this directory before implementation or
oracle selection. Each specification must have an autonomous positive and
negative checker, an explicit limitation section, and a result bound to the
exact task revision and specification digest.

## AR-0022 cross-adapter conformance

`adapter-conformance-v1.json` and its fixture define shared normalized
event/capability assertions for the Codex-style, OpenCode-style, and
OpenDesk-style contracts. Run the offline checker with:

```text
python3 scripts/check_adapter_conformance.py \
  --spec specifications/adapter-conformance-v1.json \
  --record specifications/fixtures/adapter-conformance-ar0022-v1.json \
  --expected-revision 1
```

It rejects stale, private, unknown, crossed, duplicate, or tampered records
and reports capability mismatches without execution or state change.

## AR-0062 durable fair scheduling and worker leases

`durable-scheduler-v1.json` is the revision-1 scheduler kernel above the
AR-0061 durable job contract. Its reference model admits dependency-bound jobs,
applies queue backpressure, priority aging, tenant/resource reservations,
fenced worker leases, expiry/retry, checkpoint recovery, cancellation, and
idempotent dispatch. The canonical offline fixture is checked with:

```text
python3 scripts/check_durable_scheduler.py \
  --spec specifications/durable-scheduler-v1.json \
  --fixture specifications/fixtures/durable-scheduler-ar0062-v1.json \
  --expected-revision 1
```

The checker evaluates supplied deterministic observations only. It performs no
Coordinator mutation, persistence, worker execution, provider or LLM call,
network access, or live-service operation.

## AR-0025 security, privacy, and supply-chain assurance

`security-privacy-supply-chain-v1.json` and its fixture bind bounded
secret-handling, least-privilege, dependency-provenance, redaction,
public-evidence, and hostile-boundary observations to AR-0025 revision 1.
The checker requires exact dependency versions and digest references, rejects
private or credential-bearing content, and performs no scanner, network,
provider, package-manager, Git, or durable-state operation.

Specifications are contract evidence, not implementation-refinement proofs.
They must not contain credentials, private paths, prompts, transcripts, host
identifiers, or unbounded command output.

## AR-0024 operational CLI, configuration, and onboarding

`operational-cli-v1.json` defines the versioned, provider-neutral command and
state contract. Its fixture covers setup, run, observe, acknowledged
interruption, checkpoint-bound resume, diagnosis, and safe shutdown. Validate
it offline with:

```text
python3 scripts/check_operational_cli.py \
  --spec specifications/operational-cli-v1.json \
  --fixture specifications/fixtures/operational-cli-ar0024-v1.json \
  --expected-revision 3
```

The checker rejects stale, crossed, malformed, replayed, privacy-bearing, and
unauthorized traces. It performs no CLI, process, provider, network, Git,
Coordinator, AWQ, AWG, UI, or durable-state operation. `not_performed` and
`unverified` are explicit limitations, not success claims.

## AR-0026 performance and reliability qualification

`performance-reliability-qualification-v1.json` defines the five required
qualification dimensions and distinguishes supplied qualification from live
measurement. Run its offline checker with:

```text
python3 scripts/check_performance_reliability.py \
  --spec specifications/performance-reliability-qualification-v1.json \
  --record specifications/fixtures/performance-reliability-ar0026-v1.json \
  --expected-revision 1
```

The checker rejects stale, replayed, over-budget, privacy-bearing, tampered,
or live-measurement claims. It does not execute a benchmark or verify the
truth or provenance of supplied values.

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

## AR-0017 provider-neutral OpenDesk-style adapter

`opendesk-adapter-v1.json` defines a provider-neutral capability projection
and normalized request outcome for an OpenDesk-style adapter. The reference
model is `scripts/opendesk_adapter.py`; it has no provider, process, network,
credential, or LLM connection. A known capability that is not advertised is
returned as `unsupported_capability` with `execute: false` and no lifecycle
state change. Unknown capabilities and malformed or stale inputs are rejected
without state change. `scripts/check_opendesk_adapter.py` checks the exact
revision-5 trace:

```text
python3 scripts/check_opendesk_adapter.py \\
  --spec specifications/opendesk-adapter-v1.json \\
  --trace specifications/fixtures/opendesk-trace-ar0017-v1.json \\
  --expected-revision 5
```

This is a contract and evidence check only. It does not establish OpenDesk or
any provider availability, authorization, implementation support, streaming,
tool/file execution, remote runtime success, or hosted CI.

## AR-0019 capability broker and worktree enforcement

`capability-broker-v1.json` defines the revision-1-bound provider-neutral
grant, exact project/worktree/session identity, and fail-closed tool-action
enforcement. `scripts/capability_broker.py` is the in-memory model and
`scripts/check_capability_broker.py` checks the positive fixture and its
canonical evidence. Hostile tests cover stale, replayed, unknown, private,
cross-worktree, cross-project, and unauthorized-tool input.

Run it offline:

```text
python3 scripts/check_capability_broker.py \
  --spec specifications/capability-broker-v1.json \
  --trace specifications/fixtures/capability-broker-ar0019-v1.json \
  --expected-revision 1
```

The exclusive worktree value is only a supplied observation. This contract
does not inspect or prove filesystem isolation and performs no provider,
network, process, or durable-state operation.

## AR-0016 OpenCode-style normalized adapter

`opencode-adapter-v1.json` defines a provider-neutral mapping from synthetic,
bounded OpenCode-style native envelopes to normalized session events. Session
creation, message parts, tool start/completion, file changes, failure, and
completion each have a fixed normalized event and disposition. Only opaque
payload digests, identifiers, and bounded counts cross the boundary; prompts,
transcripts, paths, credentials, and raw output are rejected.

Run the offline replay checker with:

```text
python3 scripts/check_opencode_adapter.py \\
  --spec specifications/opencode-adapter-v1.json \\
  --replay specifications/fixtures/opencode-replay-ar0016-v1.json \\
  --expected-revision 5
```

The fixture is synthetic replay evidence only. The checker proves canonical
mapping and exact revision/session/worktree binding; it does not launch
OpenCode or any provider, use a network, consult Coordinator, or establish
provider/runtime success.

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

## AR-0014 formal runtime model

`runtime-model-v1.json` is the revision-1-bound normative model for runtime
lifecycle, oracle, recovery, publication, reconciliation, authority, and
terminal invariants. Run its one checker offline with:

```text
python3 scripts/check_runtime_model.py \
  --spec specifications/runtime-model-v1.json \
  --trace specifications/fixtures/runtime-trace-ar0014-v1.json \
  --expected-revision 1
```

`runtime-hostile-ar0014-v1.json` names the stale, replay, authority, privacy,
and terminal corpus; focused tests add oracle, recovery, and publication
hostile cases. The model validates supplied deterministic traces only and
makes no external-tool, network, provider, LLM, Git, or durable-state call.

## AR-0009 AWQ evidence bridge

`awq-evidence-bridge-v1.json` defines the smallest versioned projection from
runtime observations to AWQ evidence. The offline model is
`scripts/awq_evidence_bridge.py`; its checker rejects stale or cross-worktree
bindings, replayed digests, privacy-bearing fields, unknown fields, and any
attempt to encode a quality decision. `quality_status` is deliberately
`not_decided`; AWQ must independently apply its requirements and acceptance
policy. No AWQ, Coordinator, provider, network, or runtime connection is made.

## AR-0010 provider-neutral AWG oracle bridge

`awg-oracle-bridge-v1.json` defines a revision-3-bound projection from bounded
runtime observations into an AWG discussion admission envelope. Exact task,
project, worktree, and session bindings are preserved. Uncertainty,
alternative evidence digests, and confidence are bounded context only; the
projection is always `admission_status: not_decided`. The model and checker
are `scripts/awg_oracle_bridge.py` and `scripts/check_awg_oracle_bridge.py`.
They reject stale, replayed, unknown, private, cross-boundary, and
decision-bearing input and perform no external operation.

## AR-0020 AWQ submission and AWG batched oracle bridge

`awq-awg-bridge-v1.json` defines the revision-1-bound bridge for unique,
digest-only evidence references and batched AWG discussion, decision, and
guidance envelopes. Runtime requests are marked `requested`; decisions and
guidance must be `received` from `awg`. Neither authority result is created by
the runtime: the projection keeps both statuses `not_decided`.

Run the deterministic checker with:

```text
python3 scripts/check_awq_awg_bridge.py \
  --spec specifications/awq-awg-bridge-v1.json \
  --record specifications/fixtures/awq-awg-bridge-ar0020-v1.json \
  --evidence specifications/fixtures/awq-awg-evidence-ar0020-v1.json \
  --expected-revision 1
```

The positive fixture and focused tests cover stale, replay, unknown, private,
cross-binding, authority, decision, and acceptance violations. This is
structural offline evidence only; no AWQ, AWG, provider, network, LLM, or
durable state is contacted.

## AR-0011 provider-neutral UI session bridge

`ui-session-bridge-v1.json` defines the revision-1-bound UI bridge. The
fixture is a bounded safe-exit trace with an exact task/project/worktree/
session/lease binding, a checkpoint, and a resumable interruption boundary.
The checker recomputes the prior trace and binding digests and rejects stale,
replayed, unknown, private, crossed, and invalid-final-event input. It does
not render a UI, accept input, acquire a lease, persist state, contact a
provider or network, or establish task completion.

```text
python3 scripts/check_ui_session_bridge.py \
  --spec specifications/ui-session-bridge-v1.json \
  --record specifications/fixtures/ui-session-trace-ar0011-v1.json \
  --evidence specifications/fixtures/ui-session-evidence-ar0011-v1.json \
  --expected-revision 1
```

## AR-0054 production UI human-gate integration

`production-ui-human-gate-v1.json` defines the revision-5-bound production-shaped
session bridge. It validates private mode-0600 session metadata, rendering-input
digests, human presence, approve/reject/clarify/timeout/cancel final events, and
one idempotent final event. Persistence remains explicitly `not_performed` in
the offline checker; no UI, Coordinator, network, or durable-state operation is
performed and rendering is never approval.

```text
python3 scripts/check_production_ui_human_gate.py \
  --spec specifications/production-ui-human-gate-v1.json \
  --record specifications/fixtures/production-ui-human-gate-ar0054-v1.json \
  --evidence specifications/fixtures/production-ui-human-gate-evidence-ar0054-v1.json \
  --expected-revision 5
```

## AR-0012 provider-neutral Git/publication evidence

`publication-bridge-v1.json` defines a revision-3-bound envelope for branch,
commit, review, merge, and publication observations. The exact branch head is
carried through all five observations. The commit requires valid signature and
signed-DCO statuses, while component evidence and the complete envelope use
canonical SHA-256 digests. Merge and publication are non-executing
`not_performed` observations.

Run the deterministic checker with:

```text
python3 scripts/check_publication_bridge.py \\
  --spec specifications/publication-bridge-v1.json \\
  --record specifications/fixtures/publication-bridge-ar0012-v1.json \\
  --evidence specifications/fixtures/publication-evidence-ar0012-v1.json \\
  --expected-revision 3
```

The checker includes hostile coverage for stale revision, replay, unknown and
private fields, wrong head, unsigned signature/DCO, and attempted merge or
publication. It is offline evidence validation only: it does not inspect Git,
verify cryptography, contact a provider or review system, merge, publish, or
mutate durable state.

## AR-0018 supervisor runtime

`supervisor-runtime-v1.json` defines the revision-1-bound supervisor admission
and lifecycle contract. The reference model and checker are
`scripts/supervisor_runtime.py` and `scripts/check_supervisor_runtime.py`:

```text
python3 scripts/check_supervisor_runtime.py \\
  --spec specifications/supervisor-runtime-v1.json \\
  --trace specifications/fixtures/supervisor-runtime-ar0018-v1.json \\
  --expected-revision 1
```

The checker validates lease ownership, lifecycle transitions, cancellation
acknowledgement, fenced recovery, terminal finality, exact binding, and
privacy-safe evidence. It performs no process, provider, network, or durable
state operation.

## AR-0013 CI and external-observation adapter

`ci-observation-adapter-v1.json` defines a revision-1-bound envelope for a
prepared hosted-check or remote-observation request, local qualification,
correlated observation, and evidence projection. The adapter requires exact
request-ID and target-digest correlation. It intentionally distinguishes
`local_qualified_remote_unverified` from any verified remote or hosted-CI
success. The model and checker are `scripts/ci_observation_adapter.py` and
`scripts/check_ci_observation_adapter.py`:

```text
python3 scripts/check_ci_observation_adapter.py \\
  --spec specifications/ci-observation-adapter-v1.json \\
  --record specifications/fixtures/ci-observation-ar0013-v1.json \\
  --evidence specifications/fixtures/ci-observation-evidence-ar0013-v1.json \\
  --expected-revision 1
```

The positive fixture is synthetic evidence only. Hostile tests cover stale
revision, replay, unknown/private values, wrong correlation, and an attempt to
promote an unverified remote success. No request is sent and no CI, provider,
network, remote, or durable-state operation occurs.

## AR-0021 publication and CI implementation bridge

`publication-ci-bridge-v1.json` defines a revision-1-bound envelope that
preserves one exact branch head through commit, review, merge handoff, and CI.
It requires valid signature and signed-DCO observations while keeping CI
`verification: unverified` and merge handoff non-executing:

```text
python3 scripts/check_publication_ci_bridge.py \\
  --spec specifications/publication-ci-bridge-v1.json \\
  --record specifications/fixtures/publication-ci-bridge-ar0021-v1.json \\
  --evidence specifications/fixtures/publication-ci-evidence-ar0021-v1.json \\
  --expected-revision 1
```

The checker validates supplied observations only and has no Git, CI, remote,
provider, network, merge, publication, or durable-state side effects.

## AR-0025 security, privacy, and supply-chain assurance

`security-privacy-supply-chain-v1.json` defines the revision-1-bound assurance
envelope and its six observation areas. Dependency records require exact
versions plus source, integrity, and license digests; public evidence is
payload-free and publication is `not_performed`.

```text
python3 scripts/check_security_privacy_supply_chain.py \\
  --spec specifications/security-privacy-supply-chain-v1.json \\
  --record specifications/fixtures/security-privacy-supply-chain-ar0025-v1.json \\
  --expected-revision 1
```

This is offline structural evidence only and performs no scanner, network,
provider, package-manager, LLM, or durable-state operation.

## AR-0023 end-to-end autonomous workflow

`autonomous-workflow-v1.json` and its positive fixture define the bounded
revision-1 workflow trace. Run the offline checker with:

```text
python3 scripts/check_autonomous_workflow.py \\
  --spec specifications/autonomous-workflow-v1.json \\
  --fixture specifications/fixtures/autonomous-workflow-ar0023-v1.json \\
  --expected-revision 1
```

The model preserves authority ownership and recovery fencing while making no
provider, network, remote, or durable-state call.

## AR-0027 fresh-clone release and compatibility lock

`fresh-clone-release-lock-v1.json` and its fixture bind clean-checkout
installation, compatibility, supplied release evidence, and exact-target
rollback preparation to AR-0027 revision 3. Run the offline checker with:

```text
python3 scripts/check_fresh_clone_release.py \
  --spec specifications/fresh-clone-release-lock-v1.json \
  --record specifications/fixtures/fresh-clone-release-ar0027-v1.json \
  --expected-revision 3
```

The checker performs no installation, package-manager, Git, publication,
provider, network, or durable-state operation.

## AR-0028 umbrella registration and maintenance

`umbrella-maintenance-v1.json` and its fixture bind registration and the
ordered Coordinator, runtime, AWQ, AWG, UI, release, and self-evolution phases
to AR-0028 revision 3. Run the offline checker with:

```text
python3 scripts/check_umbrella_maintenance.py \
  --spec specifications/umbrella-maintenance-v1.json \
  --record specifications/fixtures/umbrella-maintenance-ar0028-v1.json \
  --expected-revision 3
```

The checker performs no authority transfer, publication, provider, network,
LLM, or durable-state operation.

## AR-0058 production deployment and release

`production-deployment-release-v1.json` binds packaging, deployment,
compatibility, upgrade, rollback, and bounded release automation to AR-0058
revision 5. Its fixture requires exact artifact and compatibility digests,
supplied signature/DCO observations, and an exact prior-version rollback target.

```text
python3 scripts/check_production_deployment_release.py \
  --spec specifications/production-deployment-release-v1.json \
  --record specifications/fixtures/production-deployment-release-ar0058-v1.json \
  --expected-revision 5
```

This is offline structural evidence only: execution, publication, providers,
network, package managers, and durable state remain untouched.

## AR-0063 provider-neutral adapter protocol and capability router

`provider-adapter-protocol-v1.json` defines revision-5-bound admission,
discovery, negotiation, bounded request/stream events, tool/file references,
interruption, checkpoint/resume fencing, failure, and close. The reference
model and checker are offline only. Unknown capabilities are rejected; known
but unadvertised capabilities return `unsupported` with no execution or state
change. Inputs are digests or opaque `secret-ref:` identifiers only.

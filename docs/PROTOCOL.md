<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Protocol boundary

AWR normalizes agent-specific behavior into bounded events. Native prompts,
transcripts, credentials, host paths, and raw subprocess output are not public
evidence.

## Lifecycle

```text
admit → claim → start → checkpoint* → execute → verify → publish → reconcile
```

An event is accepted only when its task revision is current and its session is
bound to the claimed worktree. A stale, duplicated, unknown, or cross-project
event fails closed.

## Event classes

The first protocol version covers `session_started`, `plan_proposed`,
`specification_proposed`, `oracle_required`, `oracle_answered`, `tool_call`,
`file_change`, `test_result`, `formal_result`, `quality_result`,
`commit_created`, `pull_request`, `ci_update`, `checkpointed`, `interrupted`,
`failed`, and `completed`.

Each event carries a stable event ID, task ID, task revision, session ID,
adapter ID/version, bounded disposition, and a public-safe evidence digest.

AR-0002 makes this boundary machine-checkable in
`specifications/session-event-protocol-v1.json`. A trace starts with
`session_started` at sequence 1, links each later event to its immediate
predecessor, keeps one exact task revision and worktree digest, and ends at a
terminal event (`completed`, `failed`, or `interrupted`). Event, evidence, and
canonical event digests are single-use. Unknown fields, unsupported protocol
versions, privacy-bearing values, and any binding or ordering mismatch are
rejected.

## Fail-closed rules

- no claimed task means no mutation;
- no matching worktree means no mutation;
- no current revision means no event acceptance;
- no formal check for a conceptual decision means no oracle selection;
- no AWQ evidence means no quality-qualified continuation;
- no exact-head review and required CI means no merge;
- no durable state release and reconciliation means no completion claim.

The local deterministic checker is:

```text
python3 scripts/check_session_events.py \
  --trace specifications/fixtures/session-trace-ar0002-v1.json \
  --expected-revision 5
```

AR-0012 adds the provider-neutral Git/publication evidence boundary. The
record is bound to `AR-0012` Coordinator revision `3` and contains exactly one
branch, commit, review, merge, and publication observation. The branch head,
commit ID, review target, merge target, and publication target must be the
same exact Git object ID. The commit requires `signature.status: valid` and
`dco.status: signed`, with digest references for the signing key and DCO
trailer. Component evidence and the complete envelope use canonical SHA-256
digests.

```text
python3 scripts/check_publication_bridge.py \
  --spec specifications/publication-bridge-v1.json \
  --record specifications/fixtures/publication-bridge-ar0012-v1.json \
  --evidence specifications/fixtures/publication-evidence-ar0012-v1.json \
  --expected-revision 3
```

The checker rejects stale, replayed, unknown, private, wrong-head, or
unsigned-DCO evidence. It performs no Git inspection, network/provider call,
review lookup, merge, publication, or durable-state mutation; a passing result
is structural evidence only.

AR-0013 adds the provider-neutral CI and external-observation adapter. The
revision-1 record contains a prepared request, a positive local qualification,
one correlated remote observation, and a non-authoritative disposition. The
request ID and target digest must match across the request, observation, and
correlation records. A remote `success` must remain `verification: unverified`;
local qualification does not imply hosted-CI success, and unverified remote
success does not imply verified execution or quality acceptance.

```text
python3 scripts/check_ci_observation_adapter.py \
  --spec specifications/ci-observation-adapter-v1.json \
  --record specifications/fixtures/ci-observation-ar0013-v1.json \
  --evidence specifications/fixtures/ci-observation-evidence-ar0013-v1.json \
  --expected-revision 1
```

The checker rejects stale, replayed, unknown, private, wrongly correlated, or
promoted-to-verified evidence. It prepares no request and performs no CI,
provider, network, remote, Git, Coordinator, AWQ, AWG, UI, or durable-state
operation.

AR-0003 adds the adapter boundary behind this event protocol. Adapters must
report only bounded capabilities and identity, bind every lifecycle result to
the exact task revision and worktree, and accept interaction by digest
reference rather than prompts or transcripts. The reference implementation
and hostile checker are documented in `specifications/README.md`; they are
offline state-machine checks and do not establish provider availability.

The separate AR-0004 boundary checker validates the admission-side binding
that a session must have before these events can represent execution:

```text
python3 scripts/check_boundary.py \
  --spec specifications/worktree-capability-v1.json \
  --record specifications/fixtures/boundary-ar0004-v1.json \
  --expected-revision 5 \
  --expected-project agent-workflow-runtime \
  --expected-worktree agent-workflow-runtime-0004
```

It is an offline structural check. It records no private path or tool output,
and a passing result is not proof that a worktree is physically isolated or
that a provider, remote host, Coordinator, AWQ, AWG, or UI was reached.

AR-0005 adds the supervisor lifecycle protocol. A valid admission starts in
`admitted`; only the current worker/lease may start, heartbeat, cancel, hand
off, complete, or fail. Lease expiry, stale revisions, replay, cross-worker
actions, early heartbeats, invalid transitions, and privacy-bearing records are
rejected. `handoff` and `stale_recover` fence the prior lease and require a new
worker/lease before `resume`. See `specifications/supervisor-lifecycle-v1.json`
and run `python3 scripts/check_supervisor.py` for the offline trace check.

AR-0006 adds the resource and termination boundary. A resource result is
accepted only when every bounded counter and termination observation is present,
within its declared budget, and process-tree completeness is positively
observed. Cancellation is accepted only after acknowledgement. The checker
recomputes the result from the supplied deterministic observations and rejects
tampering, privacy-bearing fields, stale revisions, and unknown fields. It does
not claim actual host enforcement.

AR-0007 adds the checkpoint/recovery boundary. A checkpoint binds the exact
task revision, session, worktree, worker, lease, operation, and state/input/
result digests. An exact operation retry is idempotent; changed or ambiguous
results fail closed. Interruption must be acknowledged, and host/agent failure
can resume only after a newer fenced worker/lease replays a verified checkpoint.
The offline model and checker are `scripts/checkpoint_recovery.py` and
`scripts/check_checkpoint_recovery.py`. They validate observations only and do
not implement durable storage, process supervision, or real crash recovery.

AR-0009 adds the AWQ evidence bridge. Its projection preserves the exact task
revision and execution binding and sets `quality_status` to `not_decided`; AWQ
remains the only authority that can accept evidence. Check it with:

```text
python3 scripts/check_awq_evidence_bridge.py --spec specifications/awq-evidence-bridge-v1.json --record specifications/fixtures/evidence-bridge-ar0009-v1.json --evidence specifications/fixtures/evidence-bridge-evidence-ar0009-v1.json --expected-revision 5
```

The checker validates supplied structure and digests only. It does not submit
evidence, consult AWQ, or establish Coordinator, provider, hosted-CI, remote,
or runtime success.

AR-0020 adds the revision-1-bound AWQ/AWG bridge. Evidence crosses the
boundary as unique digest references with `offered_for_awq_review`, never as
AWQ acceptance. Oracle interaction is batched: each batch carries one
runtime-requested discussion and externally attributed AWG decision and
guidance observations. Payloads remain digest-only, and both statuses remain
`not_decided`.

```text
python3 scripts/check_awq_awg_bridge.py \
  --spec specifications/awq-awg-bridge-v1.json \
  --record specifications/fixtures/awq-awg-bridge-ar0020-v1.json \
  --evidence specifications/fixtures/awq-awg-evidence-ar0020-v1.json \
  --expected-revision 1
```

The checker rejects stale, replayed, unknown, private, cross-binding, and
runtime-authored authority envelopes. It performs no AWQ/AWG submission,
provider, network, LLM, UI, or durable-state operation.

AR-0010 adds the provider-neutral AWG oracle bridge. Runtime observations are
projected into a canonical, digest-bound `discussion_admission` envelope at
exact Coordinator task revision 3, preserving exact project, worktree, and
session bindings. Uncertainty, alternatives, and confidence are bounded
context and never an oracle decision; `admission_status` is always
`not_decided`. The offline checker rejects stale, replayed, unknown, private,
cross-binding, and decision-bearing input. It does not submit an AWG
discussion or establish Coordinator, provider, LLM, network, UI, or runtime
success.

AR-0011 adds the provider-neutral UI session bridge. Its bounded event record
is bound exactly to AR-0011 at Coordinator revision 1, the project revision,
worktree key and digest, session, and lease/worker binding. Events contain no
UI text, provider payload, prompt, transcript, credential, host identifier,
or network value. One validated final event may be `completed`, `interrupted`,
or `safe_exit`; the latter two require a referenced UI checkpoint and exact
prior-trace and binding digests for safe resume. A final event is an
observation, never a Coordinator completion, AWQ acceptance, AWG decision, or
provider result. The offline checker rejects stale, replayed, unknown,
private, cross-binding, and invalid-final-event input and performs no external
operation.

AR-0017 defines the provider-neutral OpenDesk-style adapter envelope. Its
capability report is versioned and digest-bound; requests carry only a
bounded digest reference. A known capability absent from the report is not
silently ignored or treated as success: the adapter returns
`unsupported_capability`, sets `execute` to false, and leaves its lifecycle
state unchanged. Unknown capabilities, stale task revision 5 bindings,
privacy-bearing fields, and terminal follow-up requests fail closed.

The offline model and checker are `scripts/opendesk_adapter.py` and
`scripts/check_opendesk_adapter.py`. This trace validates contract
observations only; it does not launch OpenDesk or any provider and does not
establish network, credential, LLM, remote, runtime, or hosted-CI success.

AR-0016 adds the provider-neutral OpenCode-style adapter mapping. Native
envelopes are accepted only as bounded fixture records with a kind, sequence,
the exact AR-0016 revision-5 binding, a session/worktree binding, and a payload
digest. The mapping produces deterministic normalized events for session start,
plan part, tool call, file change, failure, and completion. It never accepts or
publishes prompts, transcripts, paths, credentials, or raw output. Replay
validation is offline and synthetic; it does not launch OpenCode or any other
provider and does not prove runtime behavior.

AR-0015 adds the provider-neutral Codex-style adapter boundary. A session must
discover capabilities before starting, preserve the exact AR-0015 revision-5
task/worktree/adapter binding, and submit turns by bounded digest reference.
Interrupt, close, and failure are terminal; unknown fields, provider commands,
prompts, transcripts, private values, stale bindings, and replayed records are
rejected. The deterministic checker is:

```text
python3 scripts/check_codex_adapter.py \\
  --spec specifications/codex-style-adapter-v1.json \\
  --trace specifications/fixtures/codex-replay-ar0015-v1.json \\
  --expected-revision 5
```

It does not launch Codex or any provider and does not connect to a network,
process, LLM, Coordinator, AWQ, AWG, or UI.

AR-0014 adds the revision-1 formal runtime model. Its one checker accepts a
complete positive trace only when lifecycle transitions, exact task/worktree
binding, single-use events, authority ownership, external oracle decision,
fenced recovery, publication `not_performed`, reconciliation, terminal
finality, and privacy-safe digests all hold. Hostile traces cover stale,
replayed, authority-confused, privacy-bearing, oracle, recovery, publication,
and terminal inputs. This is offline structural evidence only.

## AR-0018 supervisor runtime

`supervisor-runtime-v1.json` binds admission and every lifecycle action to the
exact revision, project, worktree, session, worker, and lease. Start, cancel,
acknowledge, handoff, stale recovery, resume, complete, and fail transitions
are checked fail-closed; cancellation requires acknowledgement and recovery
fences the prior worker. `scripts/supervisor_runtime.py` and
`scripts/check_supervisor_runtime.py` are offline models only and do not launch
or inspect a worker or mutate Coordinator state.

## AR-0022 cross-adapter conformance and replay

The AR-0022 envelope binds Codex-style, OpenCode-style, and OpenDesk-style
projections to Coordinator revision 1. Each adapter supplies the same
normalized event and digest-bound capability shape. Replay accepts only
contiguous, single-bound terminal traces and recomputes every event digest.
Missing capabilities are reported by adapter ID with
`disposition: capability_mismatch` and `execute: false`; this is not fallback
or an execution attempt.

```text
python3 scripts/check_adapter_conformance.py \
  --spec specifications/adapter-conformance-v1.json \
  --record specifications/fixtures/adapter-conformance-ar0022-v1.json \
  --expected-revision 1
```

The checker is deterministic and offline; it does not launch a provider,
process, network, LLM, or tool and does not prove runtime success.

## AR-0019 capability broker and worktree enforcement

`capability-broker-v1.json` binds a revision-1 capability grant to the exact
task, project revision, supplied exclusive worktree binding, session, and
allowed tool versions. Every action repeats that identity and must use one of
the granted `read`, `edit`, or `test` tools. The checker rejects stale,
replayed, unknown, private, cross-worktree, cross-project, and unauthorized
input before accepting an action:

```text
python3 scripts/check_capability_broker.py \
  --spec specifications/capability-broker-v1.json \
  --trace specifications/fixtures/capability-broker-ar0019-v1.json \
  --expected-revision 1
```

This is supplied-observation evidence only. `exclusive_supplied` is a binding
label, not a claim that the checker inspected or isolated the filesystem.
The model performs no provider, network, process, LLM, Git, Coordinator,
AWQ, AWG, UI, or durable-state operation.

## AR-0021 publication and CI implementation bridge

`publication-ci-bridge-v1.json` binds branch, commit, review, merge handoff,
and CI observations to one exact head. Signature and signed-DCO statuses are
positive supplied observations; CI remains `verification: unverified`, and
merge handoff remains non-executing. The checker performs no Git, CI, remote,
provider, network, or publication operation.

## AR-0025 security, privacy, and supply-chain assurance

`security-privacy-supply-chain-v1.json` binds six bounded observation areas to
Coordinator revision 1: secret handling, least privilege, dependency
provenance, redaction, public evidence, and hostile boundaries. Dependency
observations require exact versions plus source, integrity, and license
digests. Public evidence contains no raw payload and publication is
`not_performed`. The checker performs no scanner, network, package-manager,
provider, LLM, or durable-state operation.

## AR-0023 end-to-end autonomous workflow

`autonomous-workflow-v1.json` defines a revision-1-bound trace from plan
observation through terminal reconciliation. Each event has an owning
authority, exact session/worktree/worker/lease binding, and digest-only
payload. The checker rejects stale, replayed, out-of-order, authority-confused,
privacy-bearing, recovery, durable-state, and remote-success claims.

## AR-0026 performance and reliability qualification

`performance-reliability-qualification-v1.json` binds five bounded supplied
qualification dimensions to revision 1. The checker preserves
`source: supplied_qualification` and `live_measurement: not_performed`, and
performs no benchmark, provider, network, LLM, host, or durable-authority
operation.

## AR-0024 operational CLI, configuration, and onboarding

`operational-cli-v1.json` defines a bounded, revision-3 command trace for
setup, run, observe, interrupt, resume, diagnose, and safe shutdown. The
offline checker requires setup before run, an acknowledged checkpoint before
resume, and diagnosis before shutdown. It performs no CLI, process, provider,
network, shell, Git, Coordinator, AWQ, AWG, UI, or durable-state operation;
shutdown remains `durable_state: not_performed` and
`remote_verification: unverified`.

## AR-0027 fresh-clone release and compatibility lock

`fresh-clone-release-lock-v1.json` binds installation, compatibility, release,
and rollback observations to AR-0027 revision 3. The checker requires exact
bounded versions and digests, explicit supplied signature/DCO observations,
and an exact rollback target. Installation, publication, remote verification,
and rollback execution remain `not_performed` or `unverified`.

## AR-0028 umbrella registration and maintenance

`umbrella-maintenance-v1.json` binds the seven ordered maintenance phases to
AR-0028 revision 3. The checker preserves the authority membership and
requires self-evolution to remain proposal-only. Registration is supplied
evidence; no umbrella update, Coordinator/AWQ/AWG/UI operation, release,
publication, provider, network, LLM, or durable-state action is performed.

## AR-0029 Coordinator identity, leases, and durable events

`coordinator-live-state-v1.json` is the versioned machine-readable contract
for consuming Coordinator state. Every operation carries the exact task ID and
revision plus project, worktree, session, owner, and lease bindings. Claim is
allowed only for an unclaimed open task; heartbeat, state-event, and release
require the current owner and lease. Claim, state-event, and release advance
the task revision; heartbeat does not. The Coordinator remains authoritative
for all of these decisions.

The local harness persists a canonical JSON document and digest-linked event
chain using atomic replacement. Operation IDs provide replay/idempotency:
identical replay returns the recorded result, while changed content, stale
revision, crossed binding, unknown lease, malformed input, privacy fields, and
unauthorized transitions fail closed. The checker is an offline
qualification boundary and does not perform a live Coordinator operation.

## AR-0030 admission and session bootstrap

`session-bootstrap-v1.json` binds bootstrap actions to an exact Coordinator
task revision and project/worktree/session/owner/lease tuple. The allowed
offline lifecycle is `admitted -> active`, followed by checkpoint,
interruption, or failure; expiry and replay are rejected. Credentials,
prompts, transcripts, private paths, host identifiers, and raw output are
excluded from the evidence projection. The checker proves only the supplied
offline fixture and reports live verification as `unverified`.

## AR-0060 final pilot and operational acceptance

`final-pilot-operational-acceptance-v1.json` composes the required admission,
capability, security, readiness, reliability, chaos, deployment, publication,
and operational gates into one ordered, digest-bound offline pilot. Missing,
failed, reordered, stale, replayed, or privacy-bearing gate observations fail
closed. The checker reports `qualified_offline` only while operational
acceptance remains `blocked_pending_live_evidence`; provider, LLM, network,
host, service, Coordinator, authority, publication, and durable-state work is
not performed. This is not release, live execution, provider support, or
operational acceptance.

## AR-0061 durable revision-bound jobs

`durable-job-v1.json` defines the offline durable job envelope. A job is bound
to the exact AR-0061 task revision, project revision, exclusive worktree,
session, input digest, contract digest, and idempotency key. Its explicit
sections cover objective, inputs, dependencies, capabilities, adapters,
acceptance criteria, budgets, deadline, bounded retries, priority, tenancy,
privacy, artifacts, human gates, cancellation, idempotency, and provenance.

The reference state machine is `submitted -> admitted -> queued -> running`,
with explicit checkpoint, human-gate, cancellation, failure, and terminal
paths. Events form a contiguous digest chain; stale or crossed bindings,
duplicate events, unknown fields, privacy-bearing values, invalid transitions,
and altered provenance are rejected. Validate the canonical fixture with:

```text
python3 scripts/check_durable_job.py --spec specifications/durable-job-v1.json --fixture specifications/fixtures/durable-job-ar0061-v1.json --expected-revision 1
```

Schema evolution is additive-only with a version bump: required fields cannot
be removed, enum values cannot be reused, unknown fields are rejected, and a
reader accepts only its declared schema version. The fixture is offline
structural evidence; human-gate and remote verification remain undecided or
unverified.

## AR-0063 provider-neutral adapter protocol

AR-0063 extends the adapter boundary into a complete bounded protocol:
admission, capability discovery and negotiation, request and stream events,
tool/file references, interruption acknowledgement, checkpoint/resume
fencing, failure, and close. Every event repeats the exact revision and
session/worktree binding. Payloads are represented by SHA-256 references;
secret material can only be named by an opaque `secret-ref:` identifier.

Unknown capabilities are rejected, while known but unadvertised capabilities
yield `unsupported` with `execute: false` and `state_change: false`. The
offline checker proves only the supplied contract and deterministic
normalization; it does not prove provider support, authorization, execution,
network, or live service behavior.

## AR-0062 durable fair scheduler and worker leases

`durable-scheduler-v1.json` defines the deterministic kernel above the AR-0061
job contract. Admission validates dependencies and applies bounded queue
backpressure. Dispatch orders eligible jobs by priority plus deterministic
waiting-time aging, applies tenant concurrency limits, and reserves declared
resources. A lease is fenced by worker, lease ID, and monotonically increasing
fence; expiry releases the reservation and permits only a bounded retry or
terminal failure. Heartbeats extend the current lease only. Checkpoints are
digest references, cancellation requires worker acknowledgement, and operation
IDs replay only when their request digest is identical. Dependency failures and
terminal outcomes are reconciled deterministically.

The reference model is `scripts/durable_scheduler.py`; the checker and hostile
tests are offline and do not persist state, launch workers, contact providers,
use an LLM, or access a live service:

```text
python3 scripts/check_durable_scheduler.py --spec specifications/durable-scheduler-v1.json --fixture specifications/fixtures/durable-scheduler-ar0062-v1.json --expected-revision 1
```

## AR-0081 executable Coordinator client

`coordinator-client-v1.json` defines the bounded executable client boundary.
Every request carries exact Coordinator task/project/worktree/session/owner/
lease bindings, an opaque auth reference, a unique operation ID, and a
correlation ID. `read_revision` returns a typed revision snapshot; `write_event`
is a compare-and-swap operation that accepts only the exact expected revision.
The client retries only bounded transport faults and treats stale revisions,
changed replays, malformed responses, and correlation mismatches as failures.
Transport loss after a write may have committed produces `unknown_outcome`,
never local success; the caller can reconcile with the identical operation ID
or a subsequent revision read.

The reference implementation is `scripts/coordinator_client.py`, with the
deterministic `InProcessCoordinator` fake, hostile tests, and fixture checker
under `tests/test_coordinator_client.py` and
`scripts/check_coordinator_client.py`. It performs no network, provider, LLM,
credential, Git, or live Coordinator operation:

```text
python3 scripts/check_coordinator_client.py --spec specifications/coordinator-client-v1.json --fixture specifications/fixtures/coordinator-client-ar0081-v1.json --expected-revision 3
```

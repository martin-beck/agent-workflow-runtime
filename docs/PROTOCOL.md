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

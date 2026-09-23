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

<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Agent Workflow Runtime

Agent Workflow Runtime (AWR) is the provider-neutral execution and integration
layer for the Agent Workflow family. It connects coding-agent CLIs and session
providers to the authoritative Coordinator, Quality, Guidance, and UI
contracts without moving authority into the runtime.

## Scope

AWR is responsible for:

- supervising bounded agent sessions and worker processes;
- adapting different agent CLIs to one normalized session-event protocol;
- enforcing worktree, capability, resource, timeout, and recovery boundaries;
- translating native results into privacy-safe quality evidence;
- opening and resuming revision-bound oracle discussions;
- observing exact Git, pull-request, and CI publication state;
- checkpointing, recovering, and reconciling execution.

AWR is not a replacement for the family authorities:

- Coordinator owns task lifecycle and durable state;
- AWQ owns requirements, quality gates, and evidence policy;
- AWG owns oracle decisions and reusable guidance;
- the UI owns human-facing discussion rendering and input.

AR-0128 adds the executable provider-neutral adapter registry at
`awr_cli.agent_registry`. It stores revisioned profiles with atomic JSON
replacement and an advisory lock, and requires exact adapter identity,
capabilities, lifecycle operations, resource limits, command profiles, and
sandbox requirements. `AgentSession` and `LocalScheduler` negotiate against
the same registry revision before starting or dispatching work; duplicate,
stale, unsupported, or unsafe profiles fail closed. The built-in
`fake-alpha` and `fake-beta` adapters are deterministic local test doubles;
they never contact a provider or network.

AR-0133 binds executable sessions to `scripts/durable_coordinator.py`. The
controller reads the exact task revision, requests the claim and fenced lease,
records session events, heartbeats, and requests terminal reconciliation. The
atomic file-backed Coordinator fake covers CAS, idempotency, expiry, ambiguous
writes, and restart recovery. It is offline qualification only; hosted
Coordinator transport and provider execution remain unqualified. See
`specifications/durable-coordinator-session-v1.json`.

## Initial architecture

The initial repository defines the contracts first. Runtime implementations,
agent adapters, and supervisor behavior are added through the dependency-ordered
AR plan in the public Git-backed state repository:

`https://github.com/martin-beck/agent-workflow-runtime-state`

AR-0013 adds `specifications/ci-observation-adapter-v1.json`, a provider-neutral
revision-1-bound envelope for preparing hosted-check or remote-observation
requests and correlating supplied results. It keeps local qualification
explicitly separate from a remote `success`: the only accepted remote state is
`verification: unverified`, with disposition
`local_qualified_remote_unverified`. Its checker performs no request, CI call,
network operation, remote verification, or durable-state mutation.

The runtime must fail closed when an agent action cannot be bound to a claimed
task revision, an allowed capability, a valid worktree, a quality result, or a
durable oracle outcome.

AR-0017 adds the versioned provider-neutral OpenDesk-style adapter contract
in `specifications/opendesk-adapter-v1.json`. Its offline model explicitly
returns `unsupported_capability` without execution or state change for known
but unadvertised capabilities; it does not launch OpenDesk or any provider.

The admission root is `specifications/runtime-charter-v1.json`. Before a
design or conceptual decision is implemented, an offline admission envelope
must bind the canonical specification digest, the current Coordinator task
revision, and unique privacy-safe evidence. The checker and hostile cases are
in `scripts/check_admission.py` and `tests/test_admission.py`; run
`python3 -m unittest discover -s tests -v` from a clean checkout. This check
does not replace Coordinator, AWQ, AWG, or UI authority and cannot establish
remote, hosted-CI, provider, or runtime success.

AR-0012 adds `specifications/publication-bridge-v1.json`, a provider-neutral
Git/publication evidence envelope bound to Coordinator revision 3. It carries
one exact head through branch, commit, review, merge, and publication
observations, preserves valid signature and signed-DCO evidence by digest, and
requires merge/publication to remain `not_performed`. Its offline checker has
no Git, provider, network, or remote publication side effects.

AR-0014 adds `specifications/runtime-model-v1.json`, a revision-1-bound
formal runtime model covering lifecycle, oracle admission/decision boundaries,
fenced checkpoint recovery, publication observation, reconciliation, and
authority ownership. `scripts/runtime_model.py` and
`scripts/check_runtime_model.py` are one offline model/checker boundary; the
positive and hostile trace corpus is under `specifications/fixtures/` and the
focused tests are in `tests/test_runtime_model.py`.

AR-0018 adds the cohesive Supervisor implementation boundary in
`specifications/supervisor-runtime-v1.json`. `scripts/supervisor_runtime.py`
composes exact admission binding, fenced leases, lifecycle transitions,
cancellation acknowledgement, stale recovery, and digest-only lifecycle
evidence. Its checker is offline and does not launch workers, contact
Coordinator, or claim provider, network, remote, or durable-state success.

AR-0019 adds the provider-neutral capability broker and worktree enforcement
boundary in `specifications/capability-broker-v1.json`. The offline model and
checker bind every granted `read`, `edit`, or `test` action to task revision 1,
project, supplied exclusive worktree observation, session, and grant. Stale,
replayed, unknown, private, cross-worktree, cross-project, and unauthorized
actions fail closed. The checker does not inspect the filesystem or claim
filesystem isolation, provider, network, process, or durable-state success.

AR-0020 adds `specifications/awq-awg-bridge-v1.json`, a revision-1-bound,
provider-neutral bridge for digest-only AWQ evidence submission references and
batched AWG discussion/decision/guidance envelopes. The offline model and
checker preserve exact bindings and external AWG attribution while keeping
`quality_status` and `oracle_status` at `not_decided`. They perform no AWQ,
AWG, provider, network, LLM, or durable-state operation.

AR-0021 adds `specifications/publication-ci-bridge-v1.json`, a revision-1-bound implementation bridge joining signed-DCO publication observations, review/merge handoff, exact-head CI correlation, and explicit `verification: unverified` remote status. Its offline model/checker validate supplied evidence only; merge, publication, CI, provider, network, Git, and durable-state operations are not performed.

AR-0025 adds `specifications/security-privacy-supply-chain-v1.json`, a
revision-1-bound assurance envelope for secret handling, least privilege,
dependency provenance, redaction, public evidence, and hostile boundaries.
Exact dependency versions and integrity/license digests are required; public
evidence is payload-free and publication remains `not_performed`. Its offline
model/checker performs no scanner, network, provider, LLM, Git, package-manager,
or durable-state operation.

AR-0023 adds `specifications/autonomous-workflow-v1.json`, a revision-1-bound
offline end-to-end workflow trace covering planning, execution, quality, oracle
discussion, review, merge observation, recovery, reconciliation, and terminal
evidence. Remote verification remains unverified; the checker makes no
external or durable-state operation.

## License

AR-0022 adds `specifications/adapter-conformance-v1.json`, a revision-1-bound
cross-adapter harness for the Codex-style, OpenCode-style, and OpenDesk-style
contracts. It asserts one normalized event and capability-report shape,
recomputes event/report digests, checks deterministic replay, and returns an
explicit non-executing capability mismatch report. The model and checker are
offline only.

MIT, with the Huawei copyright notice in `LICENSE`.

AR-0026 adds `specifications/performance-reliability-qualification-v1.json`,
a revision-1-bound qualification envelope for explicit latency, throughput,
recovery, resource-use, and failure-behavior specifications. Its offline
model/checker evaluate bounded supplied observations and preserve
`live_measurement: not_performed`; they never run benchmarks or contact a
provider, network, LLM, host, or durable authority. A passing envelope is not
live measurement or production qualification.

AR-0024 adds `specifications/operational-cli-v1.json`, a provider-neutral
operator contract for setup, run, observe, interrupt, resume, diagnose, and
safe shutdown. Its offline model and checker accept only a bounded,
revision-bound command trace; they do not implement or launch a CLI. Run it
with `python3 scripts/check_operational_cli.py --spec
specifications/operational-cli-v1.json --fixture
specifications/fixtures/operational-cli-ar0024-v1.json --expected-revision 3`.
Shutdown remains `durable_state: not_performed` and
`remote_verification: unverified`, so a passing trace is not live process,
provider, filesystem, network, or remote-handoff evidence.

AR-0027 adds `specifications/fresh-clone-release-lock-v1.json`, a
revision-3-bound offline lock for clean-checkout installation observations,
exact compatibility declarations, supplied release/signature/DCO evidence,
and exact-target rollback preparation. It requires no network or credentials;
publication remains `not_performed` and remote verification remains
`unverified`. Validate with `python3 scripts/check_fresh_clone_release.py
--spec specifications/fresh-clone-release-lock-v1.json --record
specifications/fixtures/fresh-clone-release-ar0027-v1.json
--expected-revision 3`.

AR-0029 adds `specifications/coordinator-live-state-v1.json` and a local,
file-backed Coordinator-shaped harness. It models exact task identity,
project/worktree/session bindings, claims, leases, revision-fenced state
events, atomic persistence, digest-linked replay, and idempotent operation IDs.
Validate it offline with:

```text
python3 scripts/check_coordinator_state.py --spec specifications/coordinator-live-state-v1.json --record specifications/fixtures/coordinator-live-state-ar0029-v1.json --expected-revision 3
```

This does not contact or mutate the Coordinator state repository. Live
verification, providers, network, hosted CI, and remote execution remain
unverified and require a separately approved integration path.

AR-0028 adds `specifications/umbrella-maintenance-v1.json`, a revision-3-bound
offline registration and maintenance workflow for Coordinator, runtime, AWQ,
AWG, UI, release, and self-evolution phases. It preserves authority ownership
and proposal-only self-evolution; release is `not_performed` and remote
verification is `unverified`. Validate with `python3
scripts/check_umbrella_maintenance.py --spec
specifications/umbrella-maintenance-v1.json --record
specifications/fixtures/umbrella-maintenance-ar0028-v1.json
--expected-revision 3`.

AR-0030 adds the revision-bound admission, lease, and session-bootstrap
boundary in `specifications/session-bootstrap-v1.json`. It requires exact
task/project/worktree/session/owner/lease identity and rejects stale, expired,
crossed, or replayed actions. Validate it offline with:

```text
python3 scripts/check_session_bootstrap.py --spec specifications/session-bootstrap-v1.json --fixture specifications/fixtures/session-bootstrap-ar0030-v1.json --expected-revision 5
```

The fixture does not contact Coordinator, start a process, contact a provider,
use an LLM, or establish live lease validity.

AR-0058 adds `specifications/production-deployment-release-v1.json`, a
revision-5-bound offline contract for deterministic packaging, deployment
plans, exact compatibility, reversible upgrades, exact-target rollback, and
bounded release automation. Validate it with:

```text
python3 scripts/check_production_deployment_release.py --spec specifications/production-deployment-release-v1.json --record specifications/fixtures/production-deployment-release-ar0058-v1.json --expected-revision 5
```

The checker requires supplied provenance and DCO/signature observations, never
executes a package manager, deployment, upgrade, rollback, release, provider,
network, or durable-state operation, and preserves publication as
`not_performed` and remote verification as `unverified`.

AR-0061 adds the offline durable revision-bound job contract in
`specifications/durable-job-v1.json`, with its canonical fixture,
`scripts/durable_job.py` state machine, and `scripts/check_durable_job.py`
checker. It binds job policy, inputs, capabilities, budgets, deadlines,
retries, tenancy, privacy, artifacts, human gates, cancellation, idempotency,
and provenance to one exact revision. Schema evolution is additive-only with
a version bump; unknown fields, stale or crossed bindings, invalid transitions,
replays, and privacy-bearing data fail closed. Validation performs no
execution, network, provider, LLM, live-service, or durable-state operation.

AR-0062 adds the offline durable fair scheduler and worker-lease kernel in
`specifications/durable-scheduler-v1.json`. It admits AR-0061 jobs with
dependency release and queue backpressure, performs priority/aging dispatch
with tenant and resource reservations, and models fenced leases, expiry,
checkpoint recovery, cancellation acknowledgement, bounded retries,
idempotent dispatch, starvation prevention, and terminal reconciliation.
Validate it with:

```text
python3 scripts/check_durable_scheduler.py --spec specifications/durable-scheduler-v1.json --fixture specifications/fixtures/durable-scheduler-ar0062-v1.json --expected-revision 1
```

The model is deterministic and offline: it does not mutate Coordinator state,
execute workers, contact providers or live services, use an LLM, or claim
durable persistence or remote success.

AR-0081 adds `specifications/coordinator-client-v1.json` and the bounded
`scripts/coordinator_client.py` client boundary. Typed revision reads and
compare-and-swap event writes preserve the Coordinator-owned task, worktree,
session, lease, auth-reference, operation, and correlation bindings. Retries
are limited to unavailable, deadline, and timeout faults; stale revisions,
changed replays, malformed responses, and correlation mismatches fail closed.
An ambiguous write is returned as `unknown_outcome` and is never guessed
successful. The in-process fake and fixture checker use deterministic fault
injection only; no network, provider, LLM, credential, or live Coordinator
operation is performed.

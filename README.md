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

## Initial architecture

The initial repository defines the contracts first. Runtime implementations,
agent adapters, and supervisor behavior are added through the dependency-ordered
AR plan in the public Git-backed state repository:

`https://github.com/martin-beck/agent-workflow-runtime-state`

The runtime must fail closed when an agent action cannot be bound to a claimed
task revision, an allowed capability, a valid worktree, a quality result, or a
durable oracle outcome.

## License

MIT, with the Huawei copyright notice in `LICENSE`.


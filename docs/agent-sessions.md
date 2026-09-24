# Provider-neutral agent sessions

`AgentSession` is the runtime lifecycle boundary for an executable agent
adapter. It emits admission, start, and terminal events, binds an input digest,
and executes through `HostSupervisor`. The adapter is only an argv contract;
the runtime does not require a provider SDK or backend connection.

`awr agent-run` is intended for deterministic local fake adapters and CI. A
successful fake run proves lifecycle and evidence plumbing only. It does not
prove a live provider is configured, and the result explicitly reports that
host network isolation was not required but remains unverified.

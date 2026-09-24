# Closed-loop contractor

`LocalContractor` is the provider-free integration harness for the runtime
contract: submit and lease a durable job, pass mandatory authority admission,
execute a provider-neutral fake session, derive an artifact digest, obtain
post-execution AWQ/AWG/UI acceptance, complete the lease, and return bounded
accounting. A failed session is terminally recorded as rejected.

The harness is intentionally explicit about `provider_cost=not_performed` and
`network=not_required_but_host_control_unverified`; it is qualification of
control flow, not live-provider or production sandbox evidence.

# Worker action control loop

`scripts/worker_control_loop.py` executes the local reference loop for every
material worker proposal. It binds AWQ evidence admission, AWG guidance and
decision, and the UI human decision to the same task revision, proposal,
specification, test contract, and evidence digests. Run the deterministic
demonstration with:

```text
python3 scripts/worker_control_loop.py --task-id AR-0135 --revision 2
python3 -m unittest tests.test_worker_control_loop -v
```

The controller compares specification and test digests to trusted baselines;
workers cannot submit replacement baselines or author specifications, tests,
user decisions, or acceptance evidence. AWQ rejection stops the proposal.
Uncertainty or blocked work requires an explicit AWG escalation followed by a
revision-bound UI outcome. Rejection and cancellation are terminal outcomes.
Missing, stale, ambiguous, non-durable, reordered, or mismatched decisions fail
closed. Accepted decisions are written to an append-only, hash-linked local
journal; reopening verifies the chain.

`FakeAuthority` provides deterministic AWQ, AWG, and UI test adapters. The
controller interface accepts authority implementations, but this reference
does not provide or qualify live adapters. The demonstration and tests use no
provider, credential, model, network, hosted check, or live authority. Journal
durability is local file durability only; it is not Coordinator persistence or
proof of external authority acceptance. Live integrations and crash-safe
filesystem guarantees remain unverified.

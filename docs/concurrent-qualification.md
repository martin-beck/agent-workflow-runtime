# Concurrent qualification

`awr qualify-concurrent` runs two to eight isolated project bindings in
parallel. Each project gets its own scheduler state, worktree, authority
fixture, fake adapter, lease, artifact digest, and accounting result. The
qualification asserts that the heterogeneous sessions do not cross task or
project boundaries and that all complete through the same mandatory gates.

The report says `providers=not_performed`: this is deterministic runtime
qualification, not a live backend test or a production host-sandbox claim.

# Runtime security check

Run the local fail-closed security check against the user-owned runtime home:

```text
awr security-check --home /path/to/awr-home
```

It verifies owner-only permissions, rejects symlinks, bounds managed-file
size, and rejects credential-bearing JSON state. It does not claim OS-wide
sandboxing, provider security, network policy enforcement, or authority
approval; those remain separate runtime and authority gates.

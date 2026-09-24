# Multi-project registry

After `awr project-init` creates a product/state pair, register it in the
user-owned runtime home:

```text
awr project-register --name inventory-system \
  --project /path/to/inventory-system \
  --state /path/to/inventory-system-state
awr project-list
```

Registration is idempotent for the exact same binding and fails closed for a
name/path/binding conflict, missing metadata, corrupt registry, or symlink.
The registry stores local paths and binding digests only; it does not claim
Coordinator registration, leases, authority mutation, provider access, or
network access.

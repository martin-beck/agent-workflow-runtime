# New project bootstrap

Create a new local project and separate state directory with an explicit
binding:

```text
awr project-init --name inventory-system --organization example-org \
  --project /path/to/inventory-system \
  --state /path/to/inventory-system-state --preview
awr project-init --name inventory-system --organization example-org \
  --project /path/to/inventory-system \
  --state /path/to/inventory-system-state
```

Both destinations must be new or empty, must not be symlinks, and must not
contain existing managed files. The command creates product metadata, a
revision-bound project/state binding, and a minimal state record. It does not
claim Coordinator registration, create leases, provision credentials, contact
AWQ/AWG/UI, or contact a provider/backend. Those authority-owned operations
remain explicit downstream steps.

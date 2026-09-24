# Local Coordinator state adapter

The runtime includes a deterministic local Coordinator-shaped state adapter for
offline qualification:

```text
awr coord-init --state-file ./state/coordinator.json --task-id AR-0113 \
  --project-revision sha256:<64-hex> --worktree-digest sha256:<64-hex> \
  --session-id SES-LOCAL-1
awr coord-status --state-file ./state/coordinator.json
awr coord-claim --state-file ./state/coordinator.json --owner WRK-LOCAL-1 \
  --expected-revision 1
```

State writes are atomic and file-locked; revisions, lease IDs, fences, owner
identity, and terminal transitions fail closed. This is local qualification
and does not contact or replace a hosted Coordinator.

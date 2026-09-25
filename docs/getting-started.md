# Agent Workflow Runtime: first project

## Adopt an existing Git project

From the root of an existing, committed Git project, one command prepares the
local control plane and runs its first deterministic intake task:

```text
awr setup --project . --start
```

The command validates the Git checkout, creates the `.awr` binding, state, and
approved starter graph, installs or reuses the local runtime home, registers the
project, and starts the initial controlled workflow. It is idempotent and will
not overwrite conflicting managed files. By default it requires a clean
checkout; use `--allow-dirty` only when the current edits are intentional.

The starter run uses the built-in deterministic fake agent. It requires no
provider, credentials, network, or LLM connection. It verifies local control
flow and leaves the project ready for the normal authority-gated workflow;
it does not pretend to implement product code by itself. Omit `--start` to
prepare the project without running the starter task. The generated status and
graph are under `.awr/`.

This walkthrough is deliberately local and provider-free. It creates a project
and separate state directory, registers both in the runtime home, runs the
deterministic mock workflow, and inspects the local audit/security boundaries.

```text
python -m pip install agent_workflow_runtime_cli-0.1.8-py3-none-any.whl
awr install
awr project-init --name inventory-system --organization example-org \
  --project ./inventory-system --state ./inventory-system-state --preview
awr project-init --name inventory-system --organization example-org \
  --project ./inventory-system --state ./inventory-system-state
awr project-register --name inventory-system --project ./inventory-system \
  --state ./inventory-system-state
awr project-list
awr local-run --manifest project-manifest.yaml
awr board-acceptance --name board-project --organization example-org \
  --workspace ./board-project-run --umbrella-root /path/to/agent-workflow
awr audit-status
awr security-check
```

The mock run proves only deterministic local control flow and evidence
bindings. It does not claim Coordinator registration, AWQ acceptance, AWG
guidance, UI approval, provider execution, network access, or publication.
Those transitions require their owning authorities and explicit qualified
bridges.

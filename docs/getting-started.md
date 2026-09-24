# Agent Workflow Runtime: first project

This walkthrough is deliberately local and provider-free. It creates a project
and separate state directory, registers both in the runtime home, runs the
deterministic mock workflow, and inspects the local audit/security boundaries.

```text
python -m pip install agent_workflow_runtime_cli-0.1.3-py3-none-any.whl
awr install
awr project-init --name inventory-system --organization example-org \
  --project ./inventory-system --state ./inventory-system-state --preview
awr project-init --name inventory-system --organization example-org \
  --project ./inventory-system --state ./inventory-system-state
awr project-register --name inventory-system --project ./inventory-system \
  --state ./inventory-system-state
awr project-list
awr local-run --manifest project-manifest.yaml
awr audit-status
awr security-check
```

The mock run proves only deterministic local control flow and evidence
bindings. It does not claim Coordinator registration, AWQ acceptance, AWG
guidance, UI approval, provider execution, network access, or publication.
Those transitions require their owning authorities and explicit qualified
bridges.

# Local project workflow harness

This preparation harness composes the existing `awr` manifest validator, dry
run planner, and local mock initializer with a fixed synthetic event trace. It
is intended to exercise the shape of a project workflow before an end-to-end
workflow AR is implemented.

Run from the repository root:

```text
python3 scripts/check_local_project_workflow.py --manifest project-manifest.yaml
python3 -m unittest tests.test_local_project_workflow -v
```

The trace binds each event and evidence digest to the exact manifest byte
revision. The modeled order is Coordinator admission, runtime setup, fake
worker change and test evidence, AWQ acceptance, AWG repair resolution, UI
human-gate acceptance, and Coordinator terminal reconciliation. The checker
rejects omitted authority gates, changed specifications or test outcomes,
unresolved repair escalation, stale revisions, duplicate event IDs, altered
evidence, and a terminal result attributed to the runtime.

The bootstrap API creates a temporary disposable local-mock layout to confirm
the existing project structure, then removes that temporary directory. All
worker and authority events are deterministic synthetic data. There is no
provider, backend, network, LLM, credential, live authority call, durable
authority mutation, publication, or remote verification. Passing this harness
is local structural evidence only; it does not claim AR completion or
Coordinator, AWQ, AWG, or UI approval.

The same deterministic path is available through the operator entrypoint:

```text
awr local-run --manifest project-manifest.yaml
```

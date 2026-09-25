# `awr` local bootstrap CLI

This initial CLI slice validates the repository's constrained project-manifest
YAML, creates an explicitly local mock workspace, and emits a deterministic
dry-run plan. It requires Python 3.10 or later and has no runtime dependencies.

Install from a checkout with `python -m pip install .`, then use:

```text
awr validate --manifest project-manifest.yaml
awr plan --manifest project-manifest.yaml --workspace demo/mock
awr init --manifest project-manifest.yaml --workspace /tmp/demo-aw-workspace
```

To adopt an existing Git project, run this from its root:

```text
awr setup --project . --start
```

This creates the local `.awr` binding, durable state, and starter workflow,
initializes the runtime home, registers the project, and executes one
provider-free deterministic fake-agent intake task. It does not contact a
provider or require credentials. The command refuses user changes or managed
file conflicts unless `--allow-dirty` is supplied; rerunning it is safe when
the generated files are unchanged.

The exact manifest bytes determine `project_revision` (`sha256:...`). `plan`
does not inspect or write the workspace; `--expected-revision` can require an
exact revision. `init` only accepts a missing or empty destination and writes
`project/project-manifest.json` plus `.awr/local-mock/state.json`. Existing
content and symlink destinations are rejected. The state identifies itself as
local mock state and leaves provider and authority effects at
`not_performed`; network is disabled and credentials are not required.

The manifest reader implements a small YAML subset: nested mappings, quoted or
plain string scalars, and inline lists. It rejects duplicate keys, unsupported
YAML features, unknown manifest fields, malformed authority sections, and
inputs over 64 KiB. It is not a general YAML parser.

This is an operator bootstrap aid, not a Coordinator client. It does not create
leases, contact a provider, use credentials, mutate Coordinator/AWQ/AWG/UI,
start agents, or establish filesystem isolation or remote success. The mock
state is disposable local scaffolding and is not authoritative project state.

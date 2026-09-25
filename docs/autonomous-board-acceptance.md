# AR-0140 autonomous board acceptance

The board entrypoint creates a new bounded project and runs its full local
workflow in one command. It accepts only the canonical umbrella checkout at
the exact compatibility-manifest revision and confirms that the pinned runtime
release tag resolves to the manifest's immutable source commit. The runtime
under test is reported separately from that release source commit.

From a clean checkout of the canonical umbrella compatibility release:

```text
awr board-acceptance \
  --name board-project \
  --organization agent-team \
  --workspace /tmp/board-project-run \
  --umbrella-root /path/to/agent-workflow
```

The runtime compiles a seven-node dependency graph from the project identity
and bounded project template. It gets graph approval through the Coordinator
bridge, claims each task, starts local `fake-alpha` and `fake-beta` sessions
under the host supervisor, exercises expired-lease recovery from a bound
checkpoint, and routes pre-execution and artifact decisions through the
revision-bound Coordinator/AWQ/AWG/UI bridge. The repair node is ordinary
scheduled work in the generated graph. Success requires every session process
tree to be clean, every authority observation to match its task revision, and
every task to have one durable terminal reconciliation. Re-running the same
workspace is rejected rather than silently replacing its state.

The machine-readable contract is
`specifications/autonomous-board-acceptance-v1.json`; the end-to-end and
hostile regressions are in `tests/test_board_acceptance_ar0140.py`. The
privacy-safe evidence bundle is written to `state/board-evidence.json` and
contains graph, run, authority, accounting, and release-provenance digests.
It does not contain prompts, output, credentials, private paths, or host IDs.

All agent sessions and authority endpoints in this acceptance path are
deterministic local fakes. No provider configuration, key, or model is read;
no network, LLM, hosted authority, hosted CI, publication, or live UI is used.
The recorded Coordinator/AWQ/AWG/UI outcomes prove runtime routing and
revision checks against fakes, not decisions by the external authorities.
Run the repository's full CI suite and `scripts/check_tlc_authority.py`
separately; this local board result does not claim hosted checks or production
readiness.

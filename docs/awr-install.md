# AWR CLI installation and bootstrap

The `agent-workflow-runtime-cli` Python package provides the stable `awr`
entrypoint. Install it from a locally available source or wheel with
`python -m pip install <package-or-wheel>`. The package has no runtime
dependencies; bootstrapping does not contact a provider, backend, or network.

Run `awr version` (or `awr --version`) for the package version. `awr doctor`
reports whether the runtime home is initialized and whether its JSON files are
readable and compatible. The default home is `$AWR_HOME`, then
`$XDG_DATA_HOME/awr`, then `~/.local/share/awr`. All lifecycle commands accept
`--home PATH`; paths containing spaces are supported.

Use `awr install` for first initialization, `awr repair` to recreate missing
managed files, and `awr upgrade` after upgrading the Python package. Upgrade
records the prior runtime installation marker. `awr rollback` restores that
marker. `awr uninstall` removes the marker and deliberately retains
`config.json` and `state.json`, since they may contain user data.

The runtime home must be a directory owned by the current user and writable
for the current process. AWR writes only `install.json`, `config.json`, and
`state.json`; unrelated files are left alone. Config and state are created only
when absent. Valid existing config/state are preserved during repair and
upgrade. Invalid JSON, incompatible schemas, symlinks at managed paths, or an
invalid install marker fail closed with an error; back up and inspect damaged
files before changing them. An interrupted fresh bootstrap removes only files
created by that attempt. If cleanup cannot complete (for example, due to an
external filesystem failure), inspect the three managed filenames before
retrying.

Validation from a source checkout is offline:

```text
python -m unittest tests.test_awr_install
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

These checks cover package construction and local lifecycle behavior. They do
not install an operating-system service, verify every platform's permission
model, roll back Python package files, or establish provider/backend readiness.


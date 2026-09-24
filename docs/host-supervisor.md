# Local host supervisor

`awr host-run` is the deterministic local execution boundary used by runtime
qualification. It accepts an explicit argv, resolves the working directory
under an explicit project root, starts a new process group, applies CPU and
address-space limits where supported, bounds output, and kills the whole group
on timeout.

The environment starts empty. Variables must be named with `--allow-env` and
values may then be supplied with `--env NAME=value`. The supervisor never
claims that local subprocess execution is a sandbox: filesystem writes outside
the worktree, network isolation, and stronger container/OS policy require a
host adapter that implements those controls. Until then, the default network
requirement fails closed with `host_network_control_unsupported`.

Example provider-free qualification:

```text
awr host-run --root ./work --cwd ./work/project --allow-network -- python3 -c 'print("fake-agent")'
```

The result records which controls were applied and which remain unsupported;
callers must not infer enforcement from a successful exit code.

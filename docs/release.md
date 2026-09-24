# Offline release verification

Verify a locally available wheel or source artifact before installation:

```text
sha256sum dist/agent_workflow_runtime_cli-0.1.1-py3-none-any.whl
awr release-verify --artifact dist/runtime.whl --version 0.1.1 \
  --source-commit 0123456789abcdef0123456789abcdef01234567 \
  --sha256 <sha256> --rollback-version 0.1.0
```

The verifier checks the exact artifact digest, source commit shape, size,
symlink safety, and distinct rollback target. It performs no download,
publication, package installation, provider access, or network operation.
Rollback of Python package files remains an installer/platform concern; this
record is the qualification boundary and preserves the exact target metadata.

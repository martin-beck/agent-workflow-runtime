# Optional provider/backend boundary

`specifications/optional-provider-boundary-v1.json` defines the external
adapter boundary. The baseline runtime does not require credentials, network,
provider access, or an LLM. A provider adapter must be explicitly selected,
use a credential reference rather than a secret value, expose bounded and
cancellable capabilities, redact evidence, and report unsupported/unknown/
failed outcomes without treating them as success.

Validate the boundary offline:

```text
python3 scripts/check_optional_provider_boundary.py
python3 -m unittest tests.test_optional_provider_boundary
```

Provider end-to-end qualification is separate and is never inferred from this
contract, local mock tests, configuration, or a green baseline suite.

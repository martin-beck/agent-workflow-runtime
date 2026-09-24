# Versioned local authority bridge contract

`specifications/local-authority-bridge-v1.json` is the machine-readable
contract for provider-neutral local exchanges with Coordinator/AWC, AWQ, AWG,
and the UI. It defines ownership, revision/digest binding, bounded outcomes,
and the rule that autonomous workers may submit evidence but may not author
decisions, tests, or specifications.

The positive and hostile fixtures are checked offline:

```text
python3 scripts/check_local_authority_contract.py
python3 -m unittest tests.test_local_authority_contract tests.test_local_authority_bridge
```

Unknown or ambiguous responses remain blocking observations. The checker does
not contact an authority, persist state, launch a worker, use credentials, or
establish live success.

#!/usr/bin/env python3
"""Check an AR-0049 provider security fixture without external effects."""
import argparse, json, sys
from pathlib import Path

try:
    from scripts.provider_execution_security import ProviderSecurityError, canonical_bytes, sha256, validate
except ModuleNotFoundError:
    from provider_execution_security import ProviderSecurityError, canonical_bytes, sha256, validate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = json.loads(args.spec.read_text(encoding="utf-8")); record = json.loads(args.fixture.read_text(encoding="utf-8"))
        required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "controls", "failure_semantics", "offline_boundary", "limitations"}
        if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-provider-execution-security" or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != "AR-0049 at Coordinator revision 5":
            raise ProviderSecurityError("unsupported or stale specification")
        if spec["offline_boundary"] != {"provider": "not_performed", "network": "disabled", "llm": "not_performed", "credentials": "references_only"}:
            raise ProviderSecurityError("unsafe offline boundary")
        result = validate(record, args.expected_revision)
    except (OSError, json.JSONDecodeError, ProviderSecurityError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps({**result, "checker": "awr-provider-execution-security-checker/1.0.0", "specification_digest": sha256(canonical_bytes(spec)), "fixture_digest": sha256(canonical_bytes(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__": raise SystemExit(main())

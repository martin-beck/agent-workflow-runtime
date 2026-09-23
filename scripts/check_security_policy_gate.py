#!/usr/bin/env python3
"""Check an AR-0042 security policy fixture without external effects."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.security_policy_gate import SecurityPolicyError, canonical_bytes, sha256, validate
except ModuleNotFoundError:
    from security_policy_gate import SecurityPolicyError, canonical_bytes, sha256, validate

CHECKER = "awr-security-policy-gate-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityPolicyError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.fixture)
        required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "observations", "privacy", "failure_semantics", "limitations"}
        if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-security-policy-gate" or spec["version"] != "1.0.0" or spec["task"] != "AR-0042 at Coordinator revision 3" or spec["normative"] is not True:
            raise SecurityPolicyError("unsupported or stale specification")
        if args.expected_revision != 3:
            raise SecurityPolicyError("AR-0042 requires Coordinator revision 3")
        result = validate(record, 3)
    except (SecurityPolicyError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": sha256(canonical_bytes(spec)), "fixture_digest": sha256(canonical_bytes(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

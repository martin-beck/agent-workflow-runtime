#!/usr/bin/env python3
"""Check AR-0025 supplied assurance observations without external effects."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.security_privacy_supply_chain import AssuranceError, canonical_bytes, sha256, validate
except ModuleNotFoundError:
    from security_privacy_supply_chain import AssuranceError, canonical_bytes, sha256, validate

CHECKER = "awr-security-privacy-supply-chain-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise AssuranceError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.record)
        required = {"schema_version", "specification_id", "version", "title", "normative", "task", "observations", "privacy", "failure_semantics", "follow_up"}
        if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-security-privacy-supply-chain" or spec["version"] != "1.0.0" or spec["task"] != "AR-0025 at Coordinator revision 1":
            raise AssuranceError("unsupported or stale specification")
        if args.expected_revision != 1:
            raise AssuranceError("AR-0025 requires Coordinator revision 1")
        result = validate(record, args.expected_revision)
    except (AssuranceError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "specification_digest": sha256(canonical_bytes(spec)), "record_digest": sha256(canonical_bytes(record))}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

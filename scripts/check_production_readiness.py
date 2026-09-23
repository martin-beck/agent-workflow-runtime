#!/usr/bin/env python3
"""Check the AR-0045 production-readiness fixture without external effects."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.production_readiness import ReadinessError, validate_record
except ModuleNotFoundError:
    from production_readiness import ReadinessError, validate_record


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReadinessError("malformed JSON") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "sections", "authority", "states", "privacy", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-production-readiness" or spec["version"] != "1.0.0" or spec["normative"] is not True or spec["task"] != {"id": "AR-0045", "revision": 5}:
        raise ReadinessError("unsupported or stale specification")
    if spec["sections"] != ["readiness", "upgrade", "rollback", "incident", "maintenance"] or not spec["limitations"] or not spec["follow_up"]:
        raise ReadinessError("incomplete specification")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load(args.spec))
        result = validate_record(load(args.fixture), args.expected_revision)
    except (ReadinessError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

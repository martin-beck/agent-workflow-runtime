#!/usr/bin/env python3
"""Check the AR-0044 ASB pilot without external effects."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.asb_pilot import PilotError, validate_record
except ModuleNotFoundError:
    from asb_pilot import PilotError, validate_record


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise PilotError("malformed JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = load(args.spec)
        required = {"schema_version", "specification_id", "version", "title", "normative", "task", "composition", "asb_observations", "privacy", "failure_semantics", "limitations"}
        if set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-asb-offline-pilot-harness" or spec["version"] != "1.0.0" or spec["task"] != {"id": "AR-0044", "revision": 3} or spec["normative"] is not True:
            raise PilotError("unsupported or stale specification")
        if args.expected_revision != 3:
            raise PilotError("AR-0044 requires Coordinator revision 3")
        result = validate_record(load(args.fixture), 3)
    except (PilotError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline checker for the AR-0041 deterministic qualification harness."""

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.performance_reliability_harness import HarnessError, PROTOCOL, TASK, canonical, digest, validate_record
except ModuleNotFoundError:
    from performance_reliability_harness import HarnessError, PROTOCOL, TASK, canonical, digest, validate_record

CHECKER = "awr-performance-reliability-harness-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError("malformed JSON") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "bindings", "bounds", "state_machine", "privacy", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != PROTOCOL["version"] or spec["normative"] is not True or spec["task"] != TASK:
        raise HarnessError("unsupported or incomplete specification")
    if spec["failure_semantics"].get("mode") != "fail_closed" or not spec["limitations"] or not spec["follow_up"]:
        raise HarnessError("missing failure semantics or follow-up")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.expected_revision != TASK["revision"]:
            raise HarnessError("expected revision is not 3")
        spec = load(args.spec); fixture = load(args.fixture); validate_spec(spec)
        result = validate_record(fixture)
        replay = json.loads(json.dumps(fixture, sort_keys=True))
        if validate_record(replay) != result:
            raise HarnessError("canonical replay changed result")
        if fixture["evidence"]["specification_digest"] != digest(spec):
            raise HarnessError("specification digest mismatch")
    except (HarnessError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

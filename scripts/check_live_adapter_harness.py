#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0032 live adapter harness."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.live_adapter_harness import HarnessError, TASK, validate_record


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "transport", "capability_admission", "trace", "privacy", "compatibility", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-live-adapter-harness" or spec["version"] != "1.0.0" or spec["task"] != TASK or spec["failure_semantics"].get("mode") != "fail_closed":
        raise HarnessError("unsupported or incomplete AR-0032 specification")
    if not spec["normative"] or not spec["limitations"] or not spec["follow_up"]:
        raise HarnessError("normative limitations and follow-up are required")


def validate_fixture(record):
    result = validate_record(record)
    if validate_record(json.loads(json.dumps(record, sort_keys=True))) != result:
        raise HarnessError("canonical replay changed result")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.expected_revision != TASK["revision"]:
            raise HarnessError("AR-0032 expected revision does not match the contract")
        validate_spec(load_json(args.spec))
        result = validate_fixture(load_json(args.fixture))
    except HarnessError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    if result["task_revision"] != args.expected_revision:
        raise HarnessError("result revision mismatch")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

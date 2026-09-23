#!/usr/bin/env python3
"""Fail-closed checker for the offline AR-0034 OpenCode lifecycle."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.opencode_live_adapter import OpenCodeLiveError, TASK, validate_record


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeLiveError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "lifecycle", "request_response", "gates", "privacy", "compatibility", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-opencode-live-adapter" or spec["version"] != "1.0.0" or spec["task"] != TASK or spec["failure_semantics"].get("mode") != "fail_closed":
        raise OpenCodeLiveError("unsupported or incomplete AR-0034 specification")
    if not spec["normative"] or not spec["limitations"] or not spec["follow_up"]:
        raise OpenCodeLiveError("normative limitations and follow-up are required")


def validate_fixture(record):
    result = validate_record(record)
    if validate_record(json.loads(json.dumps(record, sort_keys=True))) != result:
        raise OpenCodeLiveError("canonical replay changed result")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.expected_revision != TASK["revision"]:
            raise OpenCodeLiveError("AR-0034 expected revision does not match the contract")
        validate_spec(load_json(args.spec))
        result = validate_fixture(load_json(args.fixture))
    except OpenCodeLiveError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

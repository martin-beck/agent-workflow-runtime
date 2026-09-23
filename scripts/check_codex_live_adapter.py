#!/usr/bin/env python3
"""Offline checker for the AR-0033 deterministic Codex live-adapter harness."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.codex_live_adapter import LiveAdapterError, TASK, validate_record


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveAdapterError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "capabilities", "lifecycle", "request_response", "gates", "privacy", "failure_semantics", "compatibility", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-codex-live-adapter" or spec["version"] != "1.0.0" or spec["task"] != TASK:
        raise LiveAdapterError("unsupported or incomplete AR-0033 specification")
    if not spec["normative"] or spec["failure_semantics"].get("mode") != "fail_closed" or not spec["limitations"] or not spec["follow_up"]:
        raise LiveAdapterError("normative fail-closed limitations and follow-up are required")
    if spec["capabilities"] != ["discover", "start", "request", "response", "interrupt", "close", "fail"]:
        raise LiveAdapterError("invalid capability set")
    return True


def validate_fixture(record):
    result = validate_record(record)
    replay = json.loads(json.dumps(record, sort_keys=True))
    if validate_record(replay) != result:
        raise LiveAdapterError("canonical replay changed the result")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.expected_revision != TASK["revision"]:
            raise LiveAdapterError("AR-0033 requires Coordinator revision 3")
        validate_spec(load_json(args.spec))
        result = validate_fixture(load_json(args.fixture))
    except LiveAdapterError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

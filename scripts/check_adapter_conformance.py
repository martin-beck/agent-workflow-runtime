#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0022 cross-adapter conformance."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.adapter_conformance import ConformanceError, TASK, validate_record


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "adapters", "normalized_event", "capability_report", "replay", "mismatch", "invariants", "privacy", "limitations", "failure_semantics"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-adapter-conformance" or spec["version"] != "1.0.0" or spec["task"] != TASK:
        raise ConformanceError("unsupported or stale AR-0022 specification")
    if spec["adapters"] != ["codex-style", "opencode-style", "opendesk-style"] or spec["failure_semantics"].get("mode") != "fail_closed":
        raise ConformanceError("invalid adapter or failure semantics")
    if not spec["invariants"] or not spec["privacy"] or not spec["limitations"]:
        raise ConformanceError("invariants, privacy, and limitations are required")


def validate_fixture(record):
    try:
        result = validate_record(record)
        # A second independent canonical replay is the deterministic replay assertion.
        if validate_record(json.loads(json.dumps(record, sort_keys=True))) != result:
            raise ConformanceError("replay changed under canonical serialization")
        return result
    except (ConformanceError, TypeError, AttributeError) as exc:
        raise ConformanceError(str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.expected_revision != 1:
            raise ConformanceError("AR-0022 requires Coordinator revision 1")
        validate_spec(load_json(args.spec))
        result = validate_fixture(load_json(args.record))
    except ConformanceError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0016 replay contract."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.opencode_adapter import OpenCodeAdapterError, canonical_bytes, digest, replay


class ContractError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "task", "mapping", "invariants", "limitations", "follow_up", "privacy", "limits"}
    if not isinstance(spec, dict) or spec.get("schema_version") != 1 or not required.issubset(spec) or spec["specification_id"] != "awr-opencode-style-adapter" or spec["version"] != "1.0.0" or spec["task"] != {"id": "AR-0016", "revision": 5}:
        raise ContractError("unsupported, incomplete, or stale specification")
    if len(spec["mapping"]) != 7 or spec["limits"] != {"max_events": 64, "max_identifier": 64, "max_count": 1000000}:
        raise ContractError("mapping or limits are invalid")
    return True


def validate_replay(record, expected_revision=5):
    if not isinstance(record, dict) or set(record) != {"task", "native", "normalized"} or record["task"] != {"id": "AR-0016", "revision": expected_revision}:
        raise ContractError("invalid replay envelope or task revision")
    try:
        expected = replay(record["native"], expected_revision)
    except (OpenCodeAdapterError, AttributeError, TypeError) as exc:
        raise ContractError(str(exc)) from exc
    if record["normalized"] != expected:
        raise ContractError("normalized replay does not match canonical mapping")
    if len({event["event_digest"] for event in expected}) != len(expected):
        raise ContractError("duplicate normalized event digest")
    return {"contract": "awr-opencode-style-adapter@1.0.0", "events": len(expected), "task_revision": expected_revision, "terminal_event": expected[-1]["event_type"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--replay", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load_json(args.spec))
        result = validate_replay(load_json(args.replay), args.expected_revision)
    except (ContractError, OpenCodeAdapterError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

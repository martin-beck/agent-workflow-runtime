#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0054 production UI bridge."""

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.production_ui_human_gate import SessionError, canonical_bytes, persist_final_event, sha256, validate
except ModuleNotFoundError:
    from production_ui_human_gate import SessionError, canonical_bytes, persist_final_event, sha256, validate

CHECKER = "awr-production-ui-human-gate-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError("malformed JSON") from exc


def check(spec, record, evidence, expected_revision):
    if spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-production-ui-human-gate" or spec.get("version") != "1.0.0":
        raise SessionError("unsupported specification")
    result = validate(record, expected_revision)
    spec_digest = sha256(canonical_bytes(spec))
    expected = {"checker": CHECKER, "task_revision": expected_revision, "specification_digest": spec_digest, "record_digest": sha256(canonical_bytes(record)), "result": result, "persistence": persist_final_event(record), "live_verification": "unverified"}
    if evidence != expected:
        raise SessionError("mismatched checker evidence")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = check(load(args.spec), load(args.record), load(args.evidence), args.expected_revision)
    except (SessionError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER, "live_verification": "unverified"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

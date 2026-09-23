#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0053 AWG decision integration."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.awg_decision_integration import DecisionError, digest, project, validate
except ModuleNotFoundError:
    from awg_decision_integration import DecisionError, digest, project, validate

CHECKER = "awr-awg-decision-integration-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise DecisionError("malformed JSON") from exc


def check(spec, record, evidence, expected_revision):
    if spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-awg-decision-integration" or spec.get("version") != "1.0.0":
        raise DecisionError("unsupported specification")
    result = validate(record, expected_revision)
    expected = {"checker": CHECKER, "task_revision": expected_revision, "record_digest": digest(record), "projection": project(record, digest(spec)), "live_verification": "unverified"}
    if evidence != expected:
        raise DecisionError("mismatched checker evidence")
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
    except (DecisionError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({**result, "checker": CHECKER}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

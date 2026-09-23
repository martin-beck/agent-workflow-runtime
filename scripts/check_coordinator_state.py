#!/usr/bin/env python3
"""Fail-closed checker for the AR-0029 offline Coordinator fixture."""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.coordinator_state import CoordinatorError, CoordinatorHarness, canonical, digest

CHECKER = "awr-coordinator-live-state-checker/1.0.0"

def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream: return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc: raise CoordinatorError("malformed JSON") from exc

def check_spec(spec):
    if spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-coordinator-live-state" or spec.get("version") != "1.0.0" or spec.get("normative") is not True: raise CoordinatorError("unsupported specification")

def check_record(record, spec, expected_revision=3):
    check_spec(spec)
    if record.get("task", {}).get("id") != "AR-0029" or record["task"].get("revision") != expected_revision + 3: raise CoordinatorError("invalid final task revision")
    if record.get("task", {}).get("status") != "done" or record.get("session_id") != "": raise CoordinatorError("non-terminal fixture")
    harness = CoordinatorHarness()
    harness.data = record
    harness._validate_document()
    if record.get("evidence", {}).get("checker") != CHECKER or record["evidence"].get("specification_digest") != digest(spec): raise CoordinatorError("evidence mismatch")
    safe = dict(record["evidence"]); safe.pop("safe_digest", None)
    if record["evidence"].get("safe_digest") != digest(safe): raise CoordinatorError("evidence digest mismatch")
    return {"checker": CHECKER, "task_revision": expected_revision, "operations": len(record["operations"]), "events": len(record["events"]), "live_verification": "unverified"}

def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--record", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try: print(json.dumps(check_record(load(args.record), load(args.spec), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (CoordinatorError, KeyError, TypeError) as exc: print("REJECT: " + str(exc), file=sys.stderr); return 1
    return 0

if __name__ == "__main__": raise SystemExit(main())

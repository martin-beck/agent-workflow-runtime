#!/usr/bin/env python3
"""Fail-closed checker for the AR-0036 deterministic fixture."""
import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.durable_recovery import DurableSession, RecoveryError, canonical_bytes, sha256, validate_records
except ModuleNotFoundError:
    from durable_recovery import DurableSession, RecoveryError, canonical_bytes, sha256, validate_records

CHECKER = "awr-durable-recovery-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    if not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-durable-journal-recovery" or spec.get("version") != "1.0.0" or spec.get("task") != {"id": "AR-0036", "revision": 3}:
        raise RecoveryError("unsupported specification")


def validate_fixture(record, expected_revision):
    if expected_revision != 3 or not isinstance(record, dict) or record.get("task") != {"id": "AR-0036", "revision": 3}:
        raise RecoveryError("stale task revision")
    session = DurableSession(task_revision=3, session_id=record["session_id"], worker_id=record["worker_id"], lease_id=record["lease_id"])
    for action in record["actions"]:
        kind = action["kind"]
        if kind == "append":
            session.append(operation_id=action["operation_id"], event=action["event"], payload=action["payload"])
        elif kind == "checkpoint":
            session.checkpoint(**{key: action[key] for key in ("checkpoint_id", "operation_id", "state_digest", "input_digest", "result_digest")})
        elif kind == "interrupt":
            session.append(operation_id=action["operation_id"], event="interrupt", payload={})
        elif kind == "crash":
            try:
                session.append(operation_id=action["operation_id"], event="progress", payload={"step": "uncertain"}, crash=True)
            except RecoveryError as exc:
                if "ambiguous" not in str(exc):
                    raise
        elif kind == "recover":
            session.crash_recover(checkpoint_id=action["checkpoint_id"], worker=action["worker"], lease=action["lease"], fence=action["fence"])
        elif kind == "replay":
            session.replay_checkpoint(action["checkpoint_id"])
        else:
            raise RecoveryError("unknown action")
    if validate_records(session.records) != record["expected_head_digest"] or session.state != record["expected_state"]:
        raise RecoveryError("fixture result mismatch")
    return {"checker": CHECKER, "task_revision": 3, "records": len(session.records), "state": session.state, "head_digest": record["expected_head_digest"], "specification_digest": record["specification_digest"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, fixture = load(args.spec), load(args.fixture)
        validate_spec(spec)
        expected = sha256(canonical_bytes(spec))
        if fixture.get("specification_digest") != expected:
            raise RecoveryError("specification digest mismatch")
        print(json.dumps(validate_fixture(fixture, args.expected_revision), sort_keys=True, separators=(",", ":")))
        return 0
    except (RecoveryError, KeyError, TypeError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

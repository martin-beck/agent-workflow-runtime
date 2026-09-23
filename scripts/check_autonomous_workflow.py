#!/usr/bin/env python3
"""Fail-closed checker for the AR-0023 offline workflow fixture."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.autonomous_workflow import DIGEST, TASK, WorkflowError, WorkflowState, canonical_bytes, digest


class CheckError(ValueError):
    pass


TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "worker", "events", "lifecycle", "evidence"}
EVENT = {"event_id", "sequence", "operation", "authority", "state", "next_state", "task_revision", "session_id", "worktree_digest", "worker_id", "lease_id", "payload", "disposition"}


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "stages", "authorities", "invariants", "privacy", "limitations", "failure_semantics"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-autonomous-workflow" or spec["version"] != "1.0.0" or spec["task"] != TASK or spec["normative"] is not True:
        raise CheckError("unsupported or stale AR-0023 specification")
    if not spec["stages"] or not spec["invariants"] or spec["failure_semantics"].get("mode") != "fail_closed":
        raise CheckError("incomplete specification")


def validate_record(record, expected_revision=1, expected_worktree="agent-workflow-runtime-0023"):
    if not isinstance(record, dict) or set(record) != TOP or record["schema_version"] != 1 or record["protocol"] != {"id": "awr-autonomous-workflow", "version": "1.0.0"}:
        raise CheckError("malformed workflow envelope")
    if record["task"] != {"id": "AR-0023", "revision": expected_revision}:
        raise CheckError("stale task revision")
    if record["project"] != {"key": "agent-workflow-runtime"} or record["worktree"]["key"] != expected_worktree or not DIGEST.fullmatch(record["worktree"]["digest"]):
        raise CheckError("wrong project or worktree binding")
    if set(record["worktree"]) != {"key", "digest"} or set(record["session"]) != {"id"} or set(record["worker"]) != {"id", "lease"}:
        raise CheckError("malformed identity envelope")
    if not isinstance(record["events"], list) or not record["events"] or record["lifecycle"] != {"initial": "new", "final": "terminal"}:
        raise CheckError("malformed lifecycle")
    state = WorkflowState(expected_revision, record["session"]["id"], record["worktree"]["digest"], record["worker"]["id"], record["worker"]["lease"])
    for index, event in enumerate(record["events"], 1):
        if not isinstance(event, dict) or set(event) != EVENT or event["sequence"] != index or event["state"] != state.state or event["task_revision"] != expected_revision or event["disposition"] != "observed":
            raise CheckError("event order, state, or binding mismatch")
        try:
            result = state.apply(event)
        except (WorkflowError, KeyError, TypeError) as exc:
            raise CheckError(str(exc)) from exc
        if result != event["next_state"]:
            raise CheckError("next state mismatch")
    evidence = record["evidence"]
    if set(evidence) != {"task_revision", "specification_digest", "trace_digest", "checker"} or evidence["task_revision"] != expected_revision or not DIGEST.fullmatch(evidence["specification_digest"]) or evidence["checker"] != "awr-autonomous-workflow-checker/1.0.0":
        raise CheckError("malformed evidence")
    body = dict(record)
    body.pop("evidence")
    if evidence["trace_digest"] != digest(body):
        raise CheckError("trace digest mismatch")
    if state.state != "terminal":
        raise CheckError("non-terminal workflow")
    return {"contract": "awr-autonomous-workflow@1.0.0", "task_revision": expected_revision, "events": len(record["events"]), "final": state.state, "remote_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load_json(args.spec))
        result = validate_record(load_json(args.fixture), args.expected_revision)
    except (CheckError, TypeError, KeyError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed deterministic checker for AR-0024."""
import argparse, hashlib, json, sys
from pathlib import Path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.operational_cli import DIGEST, TASK, OperationalError, OperationalState, canonical, digest

class CheckError(ValueError): pass
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "events", "lifecycle", "evidence"}

def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream: return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc: raise CheckError("malformed JSON") from exc

def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "commands", "states", "authorities", "invariants", "configuration", "failure_semantics", "privacy", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-operational-cli" or spec["version"] != "1.0.0" or spec["task"] != TASK or spec["normative"] is not True: raise CheckError("unsupported or malformed specification")
    if spec["failure_semantics"].get("mode") != "fail_closed" or set(spec["commands"]) != {"setup", "run", "observe", "interrupt", "resume", "diagnose", "shutdown"}: raise CheckError("incomplete specification")

def validate_record(record, spec, expected_revision=3, expected_worktree="agent-workflow-runtime-0024"):
    validate_spec(spec)
    if not isinstance(record, dict) or set(record) != TOP or record["schema_version"] != 1 or record["protocol"] != {"id": "awr-operational-cli", "version": "1.0.0"}: raise CheckError("malformed envelope")
    if record["task"] != {"id": "AR-0024", "revision": expected_revision} or record["project"] != {"key": "agent-workflow-runtime"}: raise CheckError("stale task or project")
    if set(record["worktree"]) != {"key", "digest"} or record["worktree"]["key"] != expected_worktree or not DIGEST.fullmatch(record["worktree"]["digest"]): raise CheckError("wrong worktree")
    if set(record["session"]) != {"id"} or not isinstance(record["events"], list) or not record["events"] or record["lifecycle"] != {"initial": "new", "final": "stopped"}: raise CheckError("malformed lifecycle")
    state = OperationalState(expected_revision, "agent-workflow-runtime", record["worktree"]["digest"], record["session"]["id"])
    for index, event in enumerate(record["events"], 1):
        if event.get("sequence") != index: raise CheckError("non-contiguous event sequence")
        try: next_state = state.apply(event)
        except (OperationalError, KeyError, TypeError) as exc: raise CheckError(str(exc)) from exc
        if event["next_state"] != next_state: raise CheckError("next state mismatch")
    evidence = record["evidence"]
    if set(evidence) != {"task_revision", "specification_digest", "trace_digest", "checker"} or evidence["task_revision"] != expected_revision or evidence["specification_digest"] != digest(spec) or evidence["checker"] != "awr-operational-cli-checker/1.0.0": raise CheckError("invalid evidence binding")
    body = dict(record); body.pop("evidence")
    if evidence["trace_digest"] != digest(body) or state.state != "stopped": raise CheckError("tampered or non-terminal trace")
    return {"contract": "awr-operational-cli@1.0.0", "task_revision": expected_revision, "commands": len(record["events"]), "final": state.state, "durable_state": "not_performed", "remote_verification": "unverified"}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try: result = validate_record(load(args.fixture), load(args.spec), args.expected_revision)
    except (CheckError, TypeError, KeyError) as exc: print("REJECT: " + str(exc), file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0
if __name__ == "__main__": raise SystemExit(main())

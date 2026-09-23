#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0007 trace contract."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from scripts.checkpoint_recovery import RecoveryError, RecoveryState
except ModuleNotFoundError:
    from checkpoint_recovery import RecoveryError, RecoveryState

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "worker", "actions", "lifecycle", "evidence"}
ACTION = {"event_id", "sequence", "operation", "worker", "lease", "state", "disposition", "payload"}


class CheckError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError(f"malformed JSON: {exc}") from exc


def _private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or _private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_private(v) for v in value)
    return isinstance(value, str) and PRIVATE.search(value) is not None


def _obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise CheckError(f"malformed {name}")
    return value


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "authority", "binding", "durability", "lifecycle", "idempotence", "failure_semantics", "privacy", "compatibility", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-checkpoint-recovery" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise CheckError("unsupported or malformed specification")
    if not spec["limitations"] or spec["failure_semantics"]["mode"] != "fail_closed":
        raise CheckError("incomplete failure semantics")


def validate_trace(trace, spec, expected_revision, expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0007"):
    validate_spec(spec)
    if not isinstance(trace, dict) or set(trace) != TOP or trace["schema_version"] != 1 or trace["protocol"] != {"id": "awr-checkpoint-recovery", "version": "1.0.0"}:
        raise CheckError("malformed protocol envelope")
    task = _obj(trace["task"], {"id", "revision"}, "task")
    if task != {"id": "AR-0007", "revision": expected_revision}:
        raise CheckError("stale task revision")
    project = _obj(trace["project"], {"key"}, "project")
    worktree = _obj(trace["worktree"], {"key", "digest"}, "worktree")
    session = _obj(trace["session"], {"id"}, "session")
    worker = _obj(trace["worker"], {"id", "lease"}, "worker")
    if project["key"] != expected_project or worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise CheckError("wrong project or worktree binding")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]) or not re.fullmatch(r"WRK-[A-Z0-9-]{1,63}", worker["id"]) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,63}", worker["lease"]):
        raise CheckError("malformed identity binding")
    lifecycle = _obj(trace["lifecycle"], {"initial", "final"}, "lifecycle")
    if lifecycle["initial"] != "active" or not isinstance(trace["actions"], list) or not trace["actions"]:
        raise CheckError("malformed lifecycle")
    state = RecoveryState(expected_revision, session["id"], worktree["key"], worker["id"], worker["lease"])
    for position, raw in enumerate(trace["actions"], 1):
        action = _obj(raw, ACTION, "action")
        if action["sequence"] != position or action["state"] != state.state or action["disposition"] not in {"accepted", "idempotent", "interrupted"}:
            raise CheckError("replayed or mismatched action")
        try:
            result = state.action(action["operation"], event_id=action["event_id"], worker=action["worker"], lease=action["lease"], payload=action["payload"])
        except (RecoveryError, TypeError, KeyError) as exc:
            raise CheckError(str(exc)) from exc
        if result != action["payload"].get("result_state", result):
            raise CheckError("result state mismatch")
    if state.state != lifecycle["final"] or _private(trace):
        raise CheckError("invalid final state or privacy violation")
    evidence = _obj(trace["evidence"], {"task_revision", "specification_digest", "checker", "safe_digest"}, "evidence")
    actual = "sha256:" + hashlib.sha256(canonical_bytes(spec)).hexdigest()
    if evidence["task_revision"] != expected_revision or evidence["specification_digest"] != actual or evidence["checker"] != "awr-checkpoint-checker/1.0.0" or not DIGEST.fullmatch(evidence["safe_digest"]):
        raise CheckError("invalid evidence binding")
    return {"protocol": "awr-checkpoint-recovery@1.0.0", "task_revision": expected_revision, "actions": len(trace["actions"]), "final": state.state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), load_json(args.spec), args.expected_revision)
    except (CheckError, KeyError, TypeError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

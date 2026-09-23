#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0014 positive and hostile traces."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from scripts.runtime_model import RuntimeModelError, RuntimeState
except ModuleNotFoundError:
    from runtime_model import RuntimeModelError, RuntimeState

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)
CHECKER = "awr-runtime-model-checker/1.0.0"
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "worker", "actions", "lifecycle", "evidence"}
ACTION = {"event_id", "sequence", "operation", "authority", "state", "task_revision", "session_id", "worktree_digest", "worker_id", "lease_id", "payload", "disposition"}


class CheckError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(private(v) for v in value)
    return isinstance(value, str) and PRIVATE.search(value) is not None


def obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise CheckError("malformed " + name)
    return value


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "revision", "authority", "lifecycle", "oracle", "recovery", "publication", "invariants", "privacy", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-runtime-model" or spec["version"] != "1.0.0" or spec["revision"] != 1 or spec["normative"] is not True:
        raise CheckError("unsupported or malformed specification")
    if not spec["limitations"] or not spec["invariants"]:
        raise CheckError("incomplete specification")


def validate_trace(trace, spec, expected_revision, expected_worktree="agent-workflow-runtime-0014"):
    validate_spec(spec)
    if not isinstance(trace, dict) or set(trace) != TOP or trace["schema_version"] != 1 or trace["protocol"] != {"id": "awr-runtime-model", "version": "1.0.0"}:
        raise CheckError("malformed protocol envelope")
    task = obj(trace["task"], {"id", "revision"}, "task")
    if task != {"id": "AR-0014", "revision": expected_revision}:
        raise CheckError("stale task revision")
    if obj(trace["project"], {"key"}, "project")["key"] != "agent-workflow-runtime":
        raise CheckError("wrong project binding")
    worktree = obj(trace["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise CheckError("wrong worktree binding")
    session = obj(trace["session"], {"id"}, "session")
    worker = obj(trace["worker"], {"id", "lease"}, "worker")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]) or not re.fullmatch(r"WRK-[A-Z0-9-]{1,63}", worker["id"]) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,63}", worker["lease"]):
        raise CheckError("malformed identity binding")
    lifecycle = obj(trace["lifecycle"], {"initial", "final"}, "lifecycle")
    if lifecycle["initial"] != "new" or not isinstance(trace["actions"], list) or not trace["actions"]:
        raise CheckError("malformed lifecycle")
    state = RuntimeState(expected_revision, session["id"], worktree["digest"], worker["id"], worker["lease"])
    for position, raw in enumerate(trace["actions"], 1):
        action = obj(raw, ACTION, "action")
        if action["sequence"] != position or action["state"] != state.state or action["task_revision"] != expected_revision or action["disposition"] != "accepted":
            raise CheckError("sequence, state, or revision mismatch")
        try:
            result = state.apply(action)
        except (RuntimeModelError, KeyError, TypeError) as exc:
            raise CheckError(str(exc)) from exc
        if result != action["payload"].get("result_state", result):
            raise CheckError("result state mismatch")
    if state.state != lifecycle["final"] or private(trace):
        raise CheckError("invalid final state or privacy violation")
    evidence = obj(trace["evidence"], {"task_revision", "specification_digest", "trace_digest", "checker"}, "evidence")
    spec_digest = "sha256:" + hashlib.sha256(canonical_bytes(spec)).hexdigest()
    trace_without_evidence = dict(trace)
    trace_without_evidence.pop("evidence")
    trace_digest = "sha256:" + hashlib.sha256(canonical_bytes(trace_without_evidence)).hexdigest()
    if evidence != {"task_revision": expected_revision, "specification_digest": spec_digest, "trace_digest": trace_digest, "checker": CHECKER}:
        raise CheckError("invalid evidence binding")
    return {"protocol": "awr-runtime-model@1.0.0", "task_revision": expected_revision, "actions": len(trace["actions"]), "final": state.state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), load_json(args.spec), args.expected_revision)
    except (CheckError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

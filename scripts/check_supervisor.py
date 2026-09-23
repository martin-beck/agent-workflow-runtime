#!/usr/bin/env python3
"""Offline fail-closed checker for the AR-0005 supervisor contract."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from scripts.supervisor import SupervisorError, SupervisorState
except ModuleNotFoundError:  # direct invocation from the repository's scripts directory
    from supervisor import SupervisorError, SupervisorState

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
PRIVATE_KEY = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "worker", "lease", "lifecycle", "actions", "evidence"}
ACTION = {"id", "sequence", "state", "operation", "worker", "lease", "time", "disposition", "lease_expires", "new_worker", "new_lease", "new_expiry"}


class SupervisorCheckError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise SupervisorCheckError(f"malformed JSON: {exc}") from exc


def _privacy(value):
    if isinstance(value, dict):
        return any(PRIVATE_KEY.search(str(key)) or _privacy(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_privacy(child) for child in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "authority", "binding", "lease", "lifecycle", "failure_semantics", "privacy", "compatibility", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-supervisor-lifecycle" or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise SupervisorCheckError("unsupported or malformed specification")
    if spec["lifecycle"].get("states") != ["admitted", "active", "cancelling", "handed_off", "recovered", "closed", "failed"] or not spec["limitations"]:
        raise SupervisorCheckError("malformed lifecycle or limitations")


def _obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise SupervisorCheckError(f"malformed {name}")
    return value


def validate_trace(trace, spec, expected_revision, expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0005"):
    validate_spec(spec)
    if not isinstance(trace, dict) or set(trace) != TOP or trace["schema_version"] != 1 or trace["protocol"] != {"id": "awr-supervisor-lifecycle", "version": "1.0.0"}:
        raise SupervisorCheckError("malformed protocol envelope")
    task = _obj(trace["task"], {"id", "revision"}, "task")
    if task["id"] != "AR-0005" or task["revision"] != expected_revision:
        raise SupervisorCheckError("stale task revision")
    project = _obj(trace["project"], {"key", "revision"}, "project")
    worktree = _obj(trace["worktree"], {"key", "base_revision", "digest"}, "worktree")
    if project["key"] != expected_project or not REVISION.fullmatch(str(project["revision"])) or worktree["key"] != expected_worktree or not REVISION.fullmatch(str(worktree["base_revision"])) or not DIGEST.fullmatch(worktree["digest"]):
        raise SupervisorCheckError("wrong project or worktree binding")
    session = _obj(trace["session"], {"id"}, "session")
    worker = _obj(trace["worker"], {"id"}, "worker")
    lease = _obj(trace["lease"], {"id", "expires"}, "lease")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]) or not re.fullmatch(r"WRK-[A-Z0-9-]{1,63}", worker["id"]) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,63}", lease["id"]):
        raise SupervisorCheckError("malformed identity binding")
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (lease["expires"],)) or lease["expires"] <= 0:
        raise SupervisorCheckError("malformed lease")
    lifecycle = _obj(trace["lifecycle"], {"initial", "final"}, "lifecycle")
    if lifecycle["initial"] != "admitted":
        raise SupervisorCheckError("invalid initial state")
    state = SupervisorState(expected_revision, session["id"], worker["id"], lease["id"], lease["expires"])
    seen = set()
    actions = trace["actions"]
    if not isinstance(actions, list) or not actions:
        raise SupervisorCheckError("missing actions")
    for position, raw in enumerate(actions, 1):
        action = _obj(raw, ACTION, "action")
        if not re.fullmatch(r"ACT-[A-Z0-9-]{1,63}", str(action["id"])) or action["id"] in seen or action["sequence"] != position:
            raise SupervisorCheckError("replayed or malformed action")
        seen.add(action["id"])
        if action["state"] != state.state or action["disposition"] not in {"accepted", "interrupted"}:
            raise SupervisorCheckError("action state or disposition mismatch")
        try:
            state.action(action["operation"], worker=action["worker"], lease=action["lease"], now=action["time"], new_worker=action["new_worker"], new_lease=action["new_lease"], new_expiry=action["new_expiry"])
        except (SupervisorError, TypeError, KeyError) as exc:
            raise SupervisorCheckError(str(exc)) from exc
        if action["lease_expires"] != state.lease_expires:
            raise SupervisorCheckError("lease evidence does not match state")
    if state.state != lifecycle["final"] or _privacy(trace):
        raise SupervisorCheckError("invalid final state or privacy violation")
    evidence = _obj(trace["evidence"], {"task_revision", "specification_digest", "checker", "safe_digest"}, "evidence")
    actual = "sha256:" + hashlib.sha256(canonical_bytes(spec)).hexdigest()
    if evidence["task_revision"] != expected_revision or evidence["specification_digest"] != actual or evidence["checker"] != "awr-supervisor-checker/1.0.0" or not DIGEST.fullmatch(evidence["safe_digest"]):
        raise SupervisorCheckError("invalid evidence binding")
    return {"protocol": "awr-supervisor-lifecycle@1.0.0", "task_revision": expected_revision, "actions": len(actions), "final": state.state, "worker": state.worker_id}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), load_json(args.spec), args.expected_revision)
    except (SupervisorCheckError, KeyError, TypeError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

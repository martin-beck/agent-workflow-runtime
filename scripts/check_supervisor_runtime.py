#!/usr/bin/env python3
"""Check an AR-0018 Supervisor admission and lifecycle trace offline."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from scripts.supervisor_runtime import SupervisorAdmission, SupervisorRuntime, SupervisorRuntimeError, digest
except ModuleNotFoundError:
    from supervisor_runtime import SupervisorAdmission, SupervisorRuntime, SupervisorRuntimeError, digest

CHECKER = "awr-supervisor-runtime-checker/1.0.0"
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "worker", "lease", "lifecycle", "actions", "evidence"}
PRIVATE = ("credential", "password", "secret", "token", "prompt", "transcript", "private_path", "host_identifier", "personal_data", "raw_output")


class CheckError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def private(value):
    if isinstance(value, dict):
        return any(any(word in str(key).lower() for word in PRIVATE) or private(child) for key, child in value.items())
    if isinstance(value, list):
        return any(private(child) for child in value)
    return isinstance(value, str) and any(word in value.lower() for word in PRIVATE)


def obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise CheckError("malformed " + name)
    return value


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "normative", "authority", "admission", "lease", "lifecycle", "evidence", "limitations"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-supervisor-runtime" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise CheckError("unsupported or malformed specification")


def validate_trace(trace, spec, expected_revision, expected_worktree="agent-workflow-runtime-0018"):
    validate_spec(spec)
    if not isinstance(trace, dict) or set(trace) != TOP or trace["schema_version"] != 1 or trace["protocol"] != {"id": "awr-supervisor-runtime", "version": "1.0.0"}:
        raise CheckError("malformed protocol envelope")
    task = obj(trace["task"], {"id", "revision"}, "task")
    project = obj(trace["project"], {"key", "revision"}, "project")
    worktree = obj(trace["worktree"], {"key", "revision", "digest"}, "worktree")
    session = obj(trace["session"], {"id"}, "session")
    worker = obj(trace["worker"], {"id"}, "worker")
    lease = obj(trace["lease"], {"id", "expires"}, "lease")
    if task != {"id": "AR-0018", "revision": expected_revision} or project["key"] != "agent-workflow-runtime" or worktree["key"] != expected_worktree:
        raise CheckError("stale or crossed admission binding")
    admission = SupervisorAdmission(task["id"], task["revision"], project["key"], project["revision"], worktree["key"], worktree["revision"], worktree["digest"], session["id"], worker["id"], lease["id"], lease["expires"])
    try:
        runtime = SupervisorRuntime(admission)
    except (SupervisorRuntimeError, TypeError) as exc:
        raise CheckError(str(exc)) from exc
    lifecycle = obj(trace["lifecycle"], {"initial", "final"}, "lifecycle")
    if lifecycle["initial"] != "admitted" or not isinstance(trace["actions"], list) or not trace["actions"]:
        raise CheckError("malformed lifecycle")
    action_fields = {"id", "sequence", "state", "operation", "worker", "lease", "time", "lease_expires", "new_worker", "new_lease", "new_expiry"}
    for raw in trace["actions"]:
        action = obj(raw, action_fields, "action")
        if action["state"] != runtime.state or action["sequence"] != runtime.sequence + 1:
            raise CheckError("sequence or state mismatch")
        try:
            runtime.apply(action["id"], action["operation"], worker=action["worker"], lease=action["lease"], now=action["time"], new_worker=action["new_worker"], new_lease=action["new_lease"], new_expiry=action["new_expiry"])
        except (SupervisorRuntimeError, TypeError, KeyError) as exc:
            raise CheckError(str(exc)) from exc
        if action["lease_expires"] != runtime.admission.lease_expires:
            raise CheckError("lease evidence mismatch")
    if lifecycle["final"] != runtime.state or runtime.state not in {"closed", "failed"} or private(trace):
        raise CheckError("invalid terminal or privacy state")
    evidence = obj(trace["evidence"], {"task_revision", "specification_digest", "lifecycle_digest", "action_count", "final_state", "checker"}, "evidence")
    expected = {"task_revision": expected_revision, "specification_digest": digest(spec), "lifecycle_digest": digest(runtime.actions), "action_count": len(runtime.actions), "final_state": runtime.state, "checker": CHECKER}
    if evidence != expected:
        raise CheckError("invalid lifecycle evidence")
    return {"protocol": "awr-supervisor-runtime@1.0.0", "task_revision": expected_revision, "actions": len(runtime.actions), "final": runtime.state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), load_json(args.spec), args.expected_revision)
    except (CheckError, TypeError, KeyError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

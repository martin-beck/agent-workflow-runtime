#!/usr/bin/env python3
"""Fail-closed deterministic checker for the AR-0028 offline workflow."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from scripts.umbrella_maintenance import PROTOCOL, UmbrellaError, evaluate, digest
except ModuleNotFoundError:
    from umbrella_maintenance import PROTOCOL, UmbrellaError, evaluate, digest

CHECKER = "awr-umbrella-maintenance-checker/1.0.0"
TOP = {"schema_version", "protocol", "task", "project", "worktree", "registration", "maintenance", "transitions", "result", "evidence"}
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class CheckError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc


def exact(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise CheckError("malformed " + name)
    return value


def private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(key)) or private(item) for key, item in value.items())
    if isinstance(value, list):
        return any(private(item) for item in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


def validate_spec(spec):
    fields = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "registration", "states", "phases", "maintenance", "compatibility", "failure_semantics", "privacy", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != fields or spec["schema_version"] != 1 or spec["specification_id"] != "awr-umbrella-maintenance" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise CheckError("unsupported or malformed specification")
    if spec["task"] != {"id": "AR-0028", "revision": 3} or spec["phases"] != ["coordinator", "runtime", "quality", "guidance", "ui", "release", "self_evolution"]:
        raise CheckError("wrong task or phase definition")
    if not spec["limitations"] or not spec["follow_up"]:
        raise CheckError("incomplete specification")


def validate_record(record, spec, expected_revision=3, expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0028"):
    validate_spec(spec)
    if not isinstance(record, dict) or set(record) != TOP or record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise CheckError("malformed protocol envelope")
    if record["task"] != {"id": "AR-0028", "revision": expected_revision}:
        raise CheckError("stale task revision")
    project = exact(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise CheckError("wrong project binding")
    digest(project["revision"], "project revision")
    worktree = exact(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree:
        raise CheckError("wrong worktree binding")
    digest(worktree["digest"], "worktree digest")
    exact(record["registration"], {"status", "family", "runtime_key", "authority_transfer", "members"}, "registration")
    exact(record["maintenance"], {"cycle_id", "status", "release", "remote_verification", "self_evolution"}, "maintenance")
    try:
        computed = evaluate(record)
    except (UmbrellaError, KeyError, TypeError) as exc:
        raise CheckError(str(exc)) from exc
    if record["result"] != computed or private(record):
        raise CheckError("result mismatch or privacy violation")
    evidence = exact(record["evidence"], {"task_revision", "specification_digest", "record_digest", "checker"}, "evidence")
    body = {key: record[key] for key in record if key != "evidence"}
    if evidence["task_revision"] != expected_revision or evidence["specification_digest"] != sha(canonical(spec)) or evidence["record_digest"] != sha(canonical(body)) or evidence["checker"] != CHECKER:
        raise CheckError("invalid evidence binding")
    return {"protocol": "awr-umbrella-maintenance@1.0.0", "task_revision": expected_revision, **computed}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(validate_record(load(args.record), load(args.spec), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (CheckError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

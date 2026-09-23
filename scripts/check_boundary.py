#!/usr/bin/env python3
"""Offline fail-closed checker for the AR-0004 boundary contract."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
ACTION = re.compile(r"^ACT-[A-Z0-9-]{1,63}$")
PRIVATE_KEY = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)
FIELDS = {"schema_version", "protocol", "session", "task", "project", "worktree", "capabilities", "authority", "lifecycle", "actions", "evidence"}
TOOL_FIELDS = {"id", "version"}
TASK_FIELDS = {"id", "revision"}
PROJECT_FIELDS = {"key", "revision"}
WORKTREE_FIELDS = {"key", "base_revision", "digest", "isolation"}
AUTHORITY_FIELDS = {"coordinator", "quality", "guidance", "ui", "runtime"}
ACTION_FIELDS = {"id", "sequence", "state", "tool", "operation", "disposition"}


class BoundaryError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryError(f"malformed JSON: {exc}") from exc


def object_(value, name, fields):
    if not isinstance(value, dict) or set(value) != fields:
        raise BoundaryError(f"malformed {name}")
    return value


def privacy(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEY.search(str(key)):
                errors.append(f"prohibited field {location}.{key}")
            privacy(child, f"{location}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            privacy(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(f"prohibited value {location}")
    return errors


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "authority", "binding", "capabilities", "authority_rules", "lifecycle", "failure_semantics", "privacy", "compatibility", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-worktree-capability" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise BoundaryError("unsupported or malformed specification")
    if set(spec["authority"]) != AUTHORITY_FIELDS or any(not isinstance(domains, list) or not domains for domains in spec["authority"].values()):
        raise BoundaryError("malformed authority matrix")
    if spec["capabilities"].get("allowed_tools") != ["read", "edit", "test"]:
        raise BoundaryError("malformed capability policy")
    if spec["lifecycle"].get("states") != ["admitted", "active", "interrupted", "closed"]:
        raise BoundaryError("malformed lifecycle")
    if not isinstance(spec["limitations"], list) or not spec["limitations"]:
        raise BoundaryError("missing limitations")
    return True


def _validate_binding(record, expected_revision):
    task = object_(record["task"], "task", TASK_FIELDS)
    if not TASK.fullmatch(str(task["id"])) or not isinstance(task["revision"], int) or isinstance(task["revision"], bool) or task["revision"] != expected_revision:
        raise BoundaryError("stale or malformed task revision")
    project = object_(record["project"], "project", PROJECT_FIELDS)
    if not PROJECT.fullmatch(str(project["key"])) or not REVISION.fullmatch(str(project["revision"])):
        raise BoundaryError("malformed project binding")
    worktree = object_(record["worktree"], "worktree", WORKTREE_FIELDS)
    if not WORKTREE.fullmatch(str(worktree["key"])) or not REVISION.fullmatch(str(worktree["base_revision"])) or not DIGEST.fullmatch(str(worktree["digest"])) or worktree["isolation"] != "exclusive":
        raise BoundaryError("malformed or non-isolated worktree")
    session = object_(record["session"], "session", {"id"})
    if not SESSION.fullmatch(str(session["id"])):
        raise BoundaryError("malformed session binding")
    capabilities = record["capabilities"]
    if not isinstance(capabilities, list) or not capabilities or any(not isinstance(tool, dict) or set(tool) != TOOL_FIELDS or not isinstance(tool["id"], str) or tool["id"] not in {"read", "edit", "test"} or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(tool["version"])) for tool in capabilities):
        raise BoundaryError("malformed capability grant")
    authority = object_(record["authority"], "authority", AUTHORITY_FIELDS)
    if any(authority[key] != "observed" for key in ("coordinator", "quality", "guidance", "ui")) or authority["runtime"] != "enforce":
        raise BoundaryError("invalid authority boundary")
    return session, project, worktree, {tool["id"] for tool in capabilities}


def validate_boundary(record, spec, expected_revision, expected_project=None, expected_worktree=None):
    validate_spec(spec)
    if not isinstance(record, dict) or set(record) != FIELDS or record["schema_version"] != 1 or record["protocol"] != {"id": "awr-worktree-capability", "version": "1.0.0"}:
        raise BoundaryError("malformed protocol envelope")
    session, project, worktree, tools = _validate_binding(record, expected_revision)
    if expected_project is not None and project["key"] != expected_project:
        raise BoundaryError("wrong project binding")
    if expected_worktree is not None and worktree["key"] != expected_worktree:
        raise BoundaryError("wrong worktree binding")
    lifecycle = object_(record["lifecycle"], "lifecycle", {"initial", "final"})
    if lifecycle["initial"] != "admitted" or lifecycle["final"] not in {"active", "interrupted", "closed"}:
        raise BoundaryError("invalid lifecycle result")
    actions = record["actions"]
    if not isinstance(actions, list) or not actions:
        raise BoundaryError("missing actions")
    seen = set()
    state = "admitted"
    transitions = {("admitted", "start"): "active", ("active", "interrupt"): "interrupted", ("active", "close"): "closed", ("interrupted", "resume"): "active", ("interrupted", "close"): "closed"}
    for position, action in enumerate(actions, 1):
        action = object_(action, "action", ACTION_FIELDS)
        if not ACTION.fullmatch(str(action["id"])) or action["id"] in seen or action["sequence"] != position or not isinstance(action["sequence"], int) or isinstance(action["sequence"], bool):
            raise BoundaryError("replayed or malformed action")
        seen.add(action["id"])
        if action["state"] != state:
            raise BoundaryError("action state does not match lifecycle")
        if action["tool"] not in tools or action["operation"] in {"publish", "merge", "state_mutation", "authority_decision"}:
            raise BoundaryError("unauthorized tool or authority operation")
        transition_names = {operation for _, operation in transitions}
        if action["operation"] not in transition_names and action["operation"] not in {"read", "edit", "test"}:
            raise BoundaryError("unsupported operation")
        if action["operation"] in transition_names:
            state = transitions[(state, action["operation"])] if (state, action["operation"]) in transitions else (_ for _ in ()).throw(BoundaryError("invalid lifecycle transition"))
        elif state != "active" or action["disposition"] != "accepted":
            raise BoundaryError("action outside active session")
        if action["disposition"] not in {"accepted", "rejected", "interrupted"}:
            raise BoundaryError("invalid action disposition")
    if state != lifecycle["final"]:
        raise BoundaryError("lifecycle result does not match actions")
    if privacy(record):
        raise BoundaryError("privacy violation")
    evidence = object_(record["evidence"], "evidence", {"task_revision", "specification_digest", "checker", "safe_digest"})
    if evidence["task_revision"] != expected_revision or not DIGEST.fullmatch(str(evidence["specification_digest"])) or not DIGEST.fullmatch(str(evidence["safe_digest"])) or evidence["checker"] != "awr-boundary-checker/1.0.0":
        raise BoundaryError("invalid evidence binding")
    return {"protocol": "awr-worktree-capability@1.0.0", "task_revision": expected_revision, "specification_digest": evidence["specification_digest"], "project": project["key"], "worktree": worktree["key"], "session_id": session["id"], "actions": len(actions), "final": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-project", required=True)
    parser.add_argument("--expected-worktree", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_boundary(load_json(args.record), load_json(args.spec), args.expected_revision, args.expected_project, args.expected_worktree)
    except BoundaryError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

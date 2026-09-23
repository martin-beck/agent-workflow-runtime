#!/usr/bin/env python3
"""Offline fail-closed checker for the AR-0006 resource contract."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from scripts.resource_boundary import ResourceBoundaryError, evaluate
except ModuleNotFoundError:
    from resource_boundary import ResourceBoundaryError, evaluate

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
PRIVATE_KEY = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)
TOP = {"schema_version", "protocol", "task", "project", "worktree", "session", "budget", "observation", "result", "evidence"}


class ResourceCheckError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ResourceCheckError(f"malformed JSON: {exc}") from exc


def _privacy(value):
    if isinstance(value, dict):
        return any(PRIVATE_KEY.search(str(key)) or _privacy(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_privacy(child) for child in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise ResourceCheckError(f"malformed {name}")
    return value


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "authority", "binding", "budgets", "observations", "enforcement", "privacy", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-resource-boundary" or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise ResourceCheckError("unsupported or malformed specification")
    if not spec["limitations"] or spec["authority"] != "awr-enforcement":
        raise ResourceCheckError("malformed limitations or authority")


def validate_trace(trace, spec, expected_revision, expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0006"):
    validate_spec(spec)
    if not isinstance(trace, dict) or set(trace) != TOP or trace["schema_version"] != 1 or trace["protocol"] != {"id": "awr-resource-boundary", "version": "1.0.0"}:
        raise ResourceCheckError("malformed protocol envelope")
    task = _object(trace["task"], {"id", "revision"}, "task")
    if task != {"id": "AR-0006", "revision": expected_revision}:
        raise ResourceCheckError("stale task revision")
    project = _object(trace["project"], {"key", "revision"}, "project")
    worktree = _object(trace["worktree"], {"key", "base_revision", "digest"}, "worktree")
    if project["key"] != expected_project or not REVISION.fullmatch(str(project["revision"])) or worktree["key"] != expected_worktree or not REVISION.fullmatch(str(worktree["base_revision"])) or not DIGEST.fullmatch(str(worktree["digest"])):
        raise ResourceCheckError("wrong project or worktree binding")
    session = _object(trace["session"], {"id"}, "session")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", str(session["id"])):
        raise ResourceCheckError("malformed session binding")
    result = _object(trace["result"], {"accepted", "disposition", "violations"}, "result")
    try:
        expected = evaluate(trace["budget"], trace["observation"])
    except (ResourceBoundaryError, TypeError, KeyError) as exc:
        raise ResourceCheckError(str(exc)) from exc
    if result != expected or _privacy(trace):
        raise ResourceCheckError("result mismatch or privacy violation")
    evidence = _object(trace["evidence"], {"task_revision", "specification_digest", "checker", "safe_digest"}, "evidence")
    actual = "sha256:" + hashlib.sha256(canonical_bytes(spec)).hexdigest()
    if evidence["task_revision"] != expected_revision or evidence["specification_digest"] != actual or evidence["checker"] != "awr-resource-boundary-checker/1.0.0" or not DIGEST.fullmatch(str(evidence["safe_digest"])):
        raise ResourceCheckError("invalid evidence binding")
    return {"protocol": "awr-resource-boundary@1.0.0", "task_revision": expected_revision, "accepted": expected["accepted"], "violations": expected["violations"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), load_json(args.spec), args.expected_revision)
    except (ResourceCheckError, KeyError, TypeError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

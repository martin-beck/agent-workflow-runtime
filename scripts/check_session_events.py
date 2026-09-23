#!/usr/bin/env python3
"""Offline fail-closed checker for the AR-0002 normalized event protocol."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^EV-[A-Z0-9-]{1,63}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ADAPTER = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PRIVATE_KEY = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)
EVENT_TYPES = {"session_started", "plan_proposed", "specification_proposed", "oracle_required", "oracle_answered", "tool_call", "file_change", "test_result", "formal_result", "quality_result", "commit_created", "pull_request", "ci_update", "checkpointed", "interrupted", "failed", "completed"}
DISPOSITIONS = {"started", "accepted", "rejected", "blocked", "passed", "failed", "cancelled", "completed"}
TERMINAL = {"completed", "failed", "interrupted"}
FIELDS = {"schema_version", "protocol", "event_id", "event_digest", "sequence", "event_type", "task", "session", "adapter", "correlation", "disposition", "evidence_digest"}


class EventError(ValueError):
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
        raise EventError(f"malformed JSON: {exc}") from exc


def _privacy(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEY.search(str(key)):
                errors.append(f"prohibited field {location}.{key}")
            _privacy(child, f"{location}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _privacy(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(f"prohibited value {location}")
    return errors


def _object(value, name):
    if not isinstance(value, dict):
        raise EventError(f"{name} must be an object")
    return value


def validate_event(event, expected_revision):
    _object(event, "event")
    if set(event) != FIELDS:
        raise EventError("unknown or missing envelope field")
    if event["schema_version"] != 1:
        raise EventError("unsupported schema version")
    protocol = _object(event["protocol"], "protocol")
    if protocol != {"id": "awr-normalized-session-events", "version": "1.0.0"}:
        raise EventError("unsupported protocol compatibility")
    if not ID.fullmatch(str(event["event_id"])) or not DIGEST.fullmatch(str(event["event_digest"])) or not DIGEST.fullmatch(str(event["evidence_digest"])):
        raise EventError("invalid event or evidence digest identifier")
    if not isinstance(event["sequence"], int) or isinstance(event["sequence"], bool) or event["sequence"] < 1:
        raise EventError("invalid sequence")
    if not isinstance(event["event_type"], str) or event["event_type"] not in EVENT_TYPES or not isinstance(event["disposition"], str) or event["disposition"] not in DISPOSITIONS:
        raise EventError("unsupported event type or disposition")
    task = _object(event["task"], "task")
    if set(task) != {"id", "revision"} or not TASK.fullmatch(str(task["id"])) or not isinstance(task["revision"], int) or isinstance(task["revision"], bool) or task["revision"] != expected_revision:
        raise EventError("stale or malformed task revision binding")
    session = _object(event["session"], "session")
    if set(session) != {"id", "worktree_key", "worktree_digest"} or not SESSION.fullmatch(str(session["id"])) or not WORKTREE.fullmatch(str(session["worktree_key"])) or not DIGEST.fullmatch(str(session["worktree_digest"])):
        raise EventError("invalid session or worktree binding")
    adapter = _object(event["adapter"], "adapter")
    if set(adapter) != {"id", "version"} or not ADAPTER.fullmatch(str(adapter["id"])) or not SEMVER.fullmatch(str(adapter["version"])):
        raise EventError("invalid adapter binding")
    correlation = _object(event["correlation"], "correlation")
    if set(correlation) != {"session_id", "parent_event_id"} or correlation["session_id"] != session["id"] or (correlation["parent_event_id"] is not None and not ID.fullmatch(str(correlation["parent_event_id"]))):
        raise EventError("invalid correlation")
    if _privacy(event):
        raise EventError("privacy violation")
    unsigned = dict(event)
    del unsigned["event_digest"]
    if sha256(canonical_bytes(unsigned)) != event["event_digest"]:
        raise EventError("event digest mismatch")
    return event


def validate_trace(trace, expected_revision):
    if not isinstance(trace, list) or not trace:
        raise EventError("trace must be a non-empty array")
    ids, digests, evidence = set(), set(), set()
    first = None
    previous = None
    for position, event in enumerate(trace, 1):
        event = validate_event(event, expected_revision)
        if event["sequence"] != position:
            raise EventError("invalid event ordering")
        for key, seen in (("event_id", ids), ("event_digest", digests), ("evidence_digest", evidence)):
            if event[key] in seen:
                raise EventError("duplicate or replayed event material")
            seen.add(event[key])
        if first is None:
            first = event
            if event["event_type"] != "session_started" or event["correlation"]["parent_event_id"] is not None:
                raise EventError("trace must start with session_started")
        else:
            if event["correlation"]["parent_event_id"] != previous["event_id"]:
                raise EventError("invalid event correlation")
            for section in ("task", "session", "adapter"):
                if event[section] != previous[section]:
                    raise EventError("cross-session, worktree, task, or adapter mismatch")
            if previous["event_type"] in TERMINAL:
                raise EventError("event follows terminal event")
        previous = event
    if previous["event_type"] not in TERMINAL:
        raise EventError("trace must end in a terminal event")
    return {"protocol": "awr-normalized-session-events@1.0.0", "events": len(trace), "task_revision": expected_revision, "session_id": first["session"]["id"], "terminal": previous["event_type"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_trace(load_json(args.trace), args.expected_revision)
    except EventError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

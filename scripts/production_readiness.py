#!/usr/bin/env python3
"""Deterministic, non-executing AR-0045 production-readiness harness."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-production-readiness", "version": "1.0.0"}
TASK = {"id": "AR-0045", "revision": 5}
SECTIONS = ("readiness", "upgrade", "rollback", "incident", "maintenance")
SECTION_STATUS = {section: "observed" for section in SECTIONS}
SECTION_STATUS["rollback"] = "prepared"
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|network|command|executable", re.I)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReadinessError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def require_digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ReadinessError("invalid " + name)


def safe(value):
    if isinstance(value, dict):
        return not any(PRIVATE.search(str(key)) for key in value) and all(safe(item) for item in value.values())
    if isinstance(value, list):
        return all(safe(item) for item in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def _section(section, value, session, worktree):
    required = {"checks", "evidence_digest", "status", "task_revision", "worktree_digest"}
    if not isinstance(value, dict) or set(value) != required:
        raise ReadinessError("malformed " + section)
    if value["task_revision"] != 5 or value["worktree_digest"] != worktree or value["status"] != SECTION_STATUS[section]:
        raise ReadinessError("exact binding or status mismatch")
    if not isinstance(value["checks"], list) or not value["checks"] or len(value["checks"]) > 8:
        raise ReadinessError("invalid " + section + " checks")
    if len(set(value["checks"])) != len(value["checks"]) or any(not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", item) for item in value["checks"]):
        raise ReadinessError("invalid check identity")
    require_digest(value["evidence_digest"], section + " evidence digest")
    unsigned = dict(value)
    unsigned.pop("evidence_digest")
    if value["evidence_digest"] != digest(unsigned) or not safe(value):
        raise ReadinessError("tampered or privacy-bearing " + section)


def validate_record(record, expected_revision=5, expected_worktree="agent-workflow-runtime-0045"):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", *SECTIONS, "terminal", "evidence"}
    if not isinstance(record, dict) or set(record) != required or record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "AR-0045", "revision": expected_revision} or expected_revision != 5:
        raise ReadinessError("unsupported or stale production-readiness envelope")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64}:
        raise ReadinessError("invalid project binding")
    if record["worktree"] != {"key": expected_worktree, "digest": "sha256:" + "2" * 64}:
        raise ReadinessError("invalid worktree binding")
    if set(record["session"]) != {"id"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", record["session"]["id"]):
        raise ReadinessError("invalid session binding")
    session, worktree = record["session"]["id"], record["worktree"]["digest"]
    for section in SECTIONS:
        _section(section, record[section], session, worktree)
    terminal = record["terminal"]
    expected_terminal = {"status": "qualified", "execute": False, "release": "not_performed", "publication": "not_performed", "remote_verification": "unverified", "provider_execution": "unverified", "durable_state": "not_performed"}
    if terminal != expected_terminal:
        raise ReadinessError("unsafe terminal projection")
    evidence = record["evidence"]
    if set(evidence) != {"task_revision", "trace_digest", "checker"} or evidence["task_revision"] != 5 or evidence["checker"] != "awr-production-readiness-checker/1.0.0" or evidence["trace_digest"] != digest({key: value for key, value in record.items() if key != "evidence"}):
        raise ReadinessError("trace digest mismatch")
    return {"protocol": "awr-production-readiness@1.0.0", "task_revision": 5, "sections": list(SECTIONS), "status": "qualified", "release": "not_performed", "publication": "not_performed", "remote_verification": "unverified", "provider_execution": "unverified", "durable_state": "not_performed", "execute": False}

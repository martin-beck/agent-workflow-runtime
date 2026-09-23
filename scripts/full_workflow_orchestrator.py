#!/usr/bin/env python3
"""Deterministic offline full-workflow orchestration model for AR-0043."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-full-workflow-orchestrator", "version": "1.0.0"}
TASK = {"id": "AR-0043", "revision": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|network|command|executable", re.I)
COMPONENTS = ("admission", "supervisor", "adapter", "journal", "awq", "awg", "ui", "publication", "security")
ORDER = {name: index for index, name in enumerate(COMPONENTS)}
AUTHORITIES = {"admission": "coordinator", "supervisor": "supervisor", "adapter": "adapter", "journal": "journal", "awq": "awq", "awg": "awg", "ui": "ui", "publication": "publication", "security": "security"}
ALLOWED_STATUS = {"observed", "accepted", "approved", "completed", "passed", "failed", "blocked", "not_performed"}


class OrchestrationError(ValueError):
    """Raised for any fail-closed orchestration violation."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(PRIVATE.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def _d(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise OrchestrationError("invalid " + name)


class Orchestrator:
    def __init__(self, record):
        self.record = record
        self.seen = {}
        self.components = set()
        self.terminal = None

    def apply(self, operation):
        required = {"operation_id", "sequence", "component", "authority", "task_revision", "session_id", "worktree_digest", "status", "depends_on", "evidence_digest"}
        if not isinstance(operation, dict) or set(operation) != required:
            raise OrchestrationError("malformed operation")
        if operation["operation_id"] in self.seen:
            if self.seen[operation["operation_id"]] == operation:
                return "idempotent_replay"
            raise OrchestrationError("changed replay")
        if operation["task_revision"] != TASK["revision"] or operation["session_id"] != self.record["session"]["id"] or operation["worktree_digest"] != self.record["worktree"]["digest"]:
            raise OrchestrationError("exact binding mismatch")
        component = operation["component"]
        if component not in COMPONENTS or operation["authority"] != AUTHORITIES[component] or operation["status"] not in ALLOWED_STATUS:
            raise OrchestrationError("authority or status mismatch")
        if not isinstance(operation["depends_on"], list) or operation["depends_on"] != list(COMPONENTS[:ORDER[component]]):
            raise OrchestrationError("dependency ordering violation")
        if any(dep not in self.components for dep in operation["depends_on"]):
            raise OrchestrationError("dependency not observed")
        _d(operation["evidence_digest"], "evidence digest")
        expected = dict(operation); expected.pop("evidence_digest")
        if operation["evidence_digest"] != digest(expected) or not _safe(operation):
            raise OrchestrationError("tampered or privacy-bearing operation")
        if component in self.components:
            raise OrchestrationError("duplicate component observation")
        if operation["status"] == "failed":
            self.terminal = "failure"
        elif operation["status"] == "blocked":
            self.terminal = "blocked"
        self.components.add(component)
        self.seen[operation["operation_id"]] = operation
        return "accepted"

    def finish(self, terminal):
        if terminal not in {"success", "failure", "blocked"}:
            raise OrchestrationError("invalid terminal status")
        if terminal == "success":
            if self.components != set(COMPONENTS) or self.terminal is not None:
                raise OrchestrationError("partial workflow cannot succeed")
            statuses = {name: self.seen[next(key for key, item in self.seen.items() if item["component"] == name)]["status"] for name in COMPONENTS}
            if statuses != {"admission": "observed", "supervisor": "observed", "adapter": "observed", "journal": "observed", "awq": "accepted", "awg": "approved", "ui": "completed", "publication": "not_performed", "security": "passed"}:
                raise OrchestrationError("terminal success prerequisites missing")
        elif self.terminal != terminal:
            raise OrchestrationError("terminal status is not derived from observation")
        return terminal


def validate_record(record, expected_revision=3, expected_worktree="agent-workflow-runtime-0043"):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "operations", "terminal", "evidence"}
    if not isinstance(record, dict) or set(record) != required or record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "AR-0043", "revision": expected_revision} or expected_revision != 3:
        raise OrchestrationError("unsupported or stale orchestration envelope")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64}:
        raise OrchestrationError("invalid project binding")
    if record["worktree"].get("key") != expected_worktree or set(record["worktree"]) != {"key", "digest"}:
        raise OrchestrationError("invalid worktree binding")
    _d(record["worktree"]["digest"], "worktree digest")
    if set(record["session"]) != {"id"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", record["session"]["id"]):
        raise OrchestrationError("invalid session binding")
    if not isinstance(record["operations"], list) or not record["operations"]:
        raise OrchestrationError("missing operations")
    model = Orchestrator(record)
    for index, operation in enumerate(record["operations"], 1):
        if operation.get("sequence") != index:
            raise OrchestrationError("non-contiguous operation sequence")
        model.apply(operation)
    terminal = record["terminal"]
    if set(terminal) != {"status", "execute", "remote_verification", "durable_state", "publication"} or terminal["execute"] is not False or terminal["remote_verification"] != "unverified" or terminal["durable_state"] != "not_performed" or terminal["publication"] != "not_performed":
        raise OrchestrationError("unsafe terminal projection")
    if model.finish(terminal["status"]) != terminal["status"]:
        raise OrchestrationError("terminal mismatch")
    evidence = record["evidence"]
    if set(evidence) != {"task_revision", "trace_digest", "checker"} or evidence["task_revision"] != 3 or evidence["checker"] != "awr-full-workflow-orchestrator-checker/1.0.0" or evidence["trace_digest"] != digest({key: value for key, value in record.items() if key != "evidence"}):
        raise OrchestrationError("trace digest mismatch")
    return {"protocol": "awr-full-workflow-orchestrator@1.0.0", "task_revision": 3, "operations": len(record["operations"]), "terminal": terminal["status"], "execute": False, "remote_verification": "unverified"}

#!/usr/bin/env python3
"""Deterministic offline model for the AR-0041 qualification harness."""

import hashlib
import json
import math
import re

PROTOCOL = {"id": "awr-performance-reliability-harness", "version": "1.0.0"}
TASK = {"id": "AR-0041", "revision": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = {
    "session": re.compile(r"^SES-[A-Z0-9-]{1,63}$"),
    "worker": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"),
    "lease": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"),
    "operation": re.compile(r"^OP-[A-Z0-9-]{1,63}$"),
}
CATEGORIES = {"latency", "throughput", "recovery", "resource_use", "failure_behavior"}
CHAOS = {"interrupt", "adapter_failure", "supervisor_handoff", "journal_replay", "budget_exceeded"}
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|executable", re.I)


class HarnessError(ValueError):
    """Raised for any fail-closed qualification violation."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value):
    return sha(canonical(value))


def _digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise HarnessError("invalid digest")
    return value


def _safe(value):
    if isinstance(value, dict):
        return not any(PRIVATE.search(str(k)) for k in value) and all(_safe(v) for v in value.values())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise HarnessError("invalid " + name)


def _binding(item, binding):
    if item.get("task") != TASK or item.get("session_id") != binding["session_id"]:
        raise HarnessError("stale or crossed task/session binding")
    if item.get("adapter") != binding["adapter"] or item.get("supervisor") != binding["supervisor"] or item.get("journal") != binding["journal"]:
        raise HarnessError("adapter, supervisor, or journal binding mismatch")


def validate_record(record):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "adapter", "supervisor", "journal", "qualification", "metrics", "chaos", "result", "evidence"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise HarnessError("unknown, missing, or privacy-bearing envelope field")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != TASK:
        raise HarnessError("unsupported protocol or stale task revision")
    project = record["project"]
    if project != {"key": "agent-workflow-runtime", "revision": project["revision"]}:
        raise HarnessError("invalid project binding")
    _digest(project["revision"])
    worktree = record["worktree"]
    if worktree.get("key") != "agent-workflow-runtime-0041" or set(worktree) != {"key", "digest"}:
        raise HarnessError("invalid worktree binding")
    _digest(worktree["digest"])
    session = record["session"]
    if set(session) != {"id"} or not ID["session"].fullmatch(str(session["id"])):
        raise HarnessError("invalid session binding")
    adapter = record["adapter"]
    if set(adapter) != {"id", "version", "digest"} or adapter["id"] not in {"codex-style", "opencode-style", "opendesk-style"} or not re.fullmatch(r"\d+\.\d+\.\d+", str(adapter["version"])):
        raise HarnessError("invalid adapter binding")
    _digest(adapter["digest"])
    supervisor = record["supervisor"]
    if set(supervisor) != {"session_id", "worker_id", "lease_id", "lease_expires"} or supervisor["session_id"] != session["id"] or not ID["worker"].fullmatch(str(supervisor["worker_id"])) or not ID["lease"].fullmatch(str(supervisor["lease_id"])) or not isinstance(supervisor["lease_expires"], int) or supervisor["lease_expires"] < 1:
        raise HarnessError("invalid supervisor binding")
    journal = record["journal"]
    if set(journal) != {"session_id", "head_digest"} or journal["session_id"] != session["id"]:
        raise HarnessError("invalid journal binding")
    _digest(journal["head_digest"])
    binding = {"session_id": session["id"], "adapter": adapter, "supervisor": supervisor, "journal": journal}
    qualification = record["qualification"]
    if qualification != {"source": "supplied_observation", "live_measurement": "not_performed", "max_metrics": 5, "max_chaos": 5, "max_value": 1000000}:
        raise HarnessError("qualification is unbounded or live")
    metrics = record["metrics"]
    if not isinstance(metrics, list) or len(metrics) != 5:
        raise HarnessError("invalid metric count")
    seen = set()
    for item in metrics:
        if not isinstance(item, dict) or set(item) != {"id", "task", "session_id", "adapter", "supervisor", "journal", "category", "metric", "value", "unit", "limit", "operator", "evidence_digest"}:
            raise HarnessError("malformed metric")
        _binding(item, binding)
        if item["category"] not in CATEGORIES or item["category"] in seen or not re.fullmatch(r"OBS-[A-Z0-9-]{1,63}", item["id"]):
            raise HarnessError("duplicate or invalid metric category")
        seen.add(item["category"]); _number(item["value"], "metric value"); _number(item["limit"], "metric limit")
        if item["value"] > qualification["max_value"] or item["operator"] not in {"less_or_equal", "greater_or_equal"} or not _digest(item["evidence_digest"]):
            raise HarnessError("invalid metric bound")
        passed = item["value"] <= item["limit"] if item["operator"] == "less_or_equal" else item["value"] >= item["limit"]
        if not passed or item["evidence_digest"] != digest({k: item[k] for k in item if k != "evidence_digest"}):
            raise HarnessError("metric failed or was tampered")
    if seen != CATEGORIES:
        raise HarnessError("incomplete metric categories")
    chaos = record["chaos"]
    if not isinstance(chaos, list) or len(chaos) != 5:
        raise HarnessError("invalid chaos count")
    seen = set()
    for item in chaos:
        if not isinstance(item, dict) or set(item) != {"id", "task", "session_id", "adapter", "supervisor", "journal", "scenario", "disposition", "recovery", "duration_ms", "evidence_digest"}:
            raise HarnessError("malformed chaos observation")
        _binding(item, binding)
        if item["scenario"] not in CHAOS or item["scenario"] in seen or item["disposition"] != "observed" or item["recovery"] not in {"recovered", "blocked"}:
            raise HarnessError("invalid chaos disposition")
        seen.add(item["scenario"]); _number(item["duration_ms"], "chaos duration")
        if item["duration_ms"] > qualification["max_value"] or item["evidence_digest"] != digest({k: item[k] for k in item if k != "evidence_digest"}):
            raise HarnessError("invalid chaos evidence")
    if seen != CHAOS:
        raise HarnessError("incomplete chaos scenarios")
    expected_result = {"status": "qualified", "source": "supplied_observation", "live_measurement": "not_performed", "metrics": sorted(CATEGORIES), "chaos": sorted(CHAOS), "execute": False, "remote_verification": "unverified", "durable_state": "not_performed"}
    if record["result"] != expected_result:
        raise HarnessError("invalid result or live success claim")
    evidence = record["evidence"]
    expected = {"task_revision": 3, "specification_digest": evidence.get("specification_digest"), "record_digest": evidence.get("record_digest"), "checker": "awr-performance-reliability-harness-checker/1.0.0"}
    if set(evidence) != set(expected) or evidence["task_revision"] != 3 or not _digest(evidence["specification_digest"]) or evidence["record_digest"] != digest({k: record[k] for k in record if k != "evidence"}):
        raise HarnessError("invalid evidence binding")
    return {"protocol": "awr-performance-reliability-harness@1.0.0", "task_revision": 3, "status": "qualified", "metrics": 5, "chaos": 5, "live_measurement": "not_performed", "execute": False}

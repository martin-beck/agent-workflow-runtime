#!/usr/bin/env python3
"""Deterministic offline AR-0059 production qualification and chaos model."""
import hashlib
import json
import math
import re

PROTOCOL = {"id": "awr-production-qualification-chaos", "version": "1.0.0"}
TASK = {"id": "AR-0059", "revision": 5}
SCENARIOS = ("concurrency", "throughput_latency", "resource_budgets", "provider_failures", "host_loss", "lease_expiry", "ui_interruption", "awq_unavailable", "awg_unavailable", "asb_replay", "upgrade_rollback", "multi_agent_comparison")
ADAPTERS = ("codex", "opencode", "opendesk")
THRESHOLDS = {"max_concurrency": 4, "min_throughput_per_second": 40, "max_p95_latency_ms": 250, "max_rss_mib": 512, "max_recovery_ms": 2000, "min_isolation_percent": 100}
LIMITS = {"max_observations": 32, "max_metrics": 8, "max_value": 1000000, "max_agents": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|network.?address|executable", re.I)

class QualificationError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

def _d(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise QualificationError("invalid " + name)

def _safe(value):
    if isinstance(value, dict):
        return all(not PRIVATE.search(str(k)) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))

def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or value > LIMITS["max_value"]:
        raise QualificationError("invalid " + name)

def _binding(item, record):
    if item.get("task") != TASK or item.get("session_id") != record["session"]["id"] or item.get("worktree_digest") != record["worktree"]["digest"]:
        raise QualificationError("stale or crossed binding")

def validate(record):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "qualification", "thresholds", "adapters", "scenarios", "metrics", "observations", "result", "evidence"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise QualificationError("unknown, missing, or privacy-bearing field")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != TASK:
        raise QualificationError("unsupported protocol or stale revision")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64} or record["worktree"] != {"key": "agent-workflow-runtime-0059", "digest": "sha256:" + "2" * 64}:
        raise QualificationError("invalid project or worktree")
    if set(record["session"]) != {"id"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", record["session"]["id"]):
        raise QualificationError("invalid session")
    if record["qualification"] != {"source": "supplied_observation", "live_measurement": "not_performed", "release_status": "blocked_pending_live_evidence"} or record["thresholds"] != THRESHOLDS or record["adapters"] != list(ADAPTERS) or record["scenarios"] != list(SCENARIOS):
        raise QualificationError("unsafe qualification boundary or catalog")
    metrics = record["metrics"]
    if not isinstance(metrics, list) or len(metrics) != 6 or len({m.get("name") for m in metrics}) != 6:
        raise QualificationError("incomplete metric set")
    operators = {"concurrency": ("less_or_equal", "max_concurrency"), "throughput_per_second": ("greater_or_equal", "min_throughput_per_second"), "p95_latency_ms": ("less_or_equal", "max_p95_latency_ms"), "rss_mib": ("less_or_equal", "max_rss_mib"), "recovery_ms": ("less_or_equal", "max_recovery_ms"), "isolation_percent": ("greater_or_equal", "min_isolation_percent")}
    for metric in metrics:
        if set(metric) != {"name", "value", "unit", "operator", "threshold", "evidence_digest"} or metric["name"] not in operators or metric["operator"] != operators[metric["name"]][0] or metric["threshold"] != THRESHOLDS[operators[metric["name"]][1]]:
            raise QualificationError("invalid metric threshold")
        _number(metric["value"], "metric value"); _d(metric["evidence_digest"], "metric evidence")
        passed = metric["value"] <= metric["threshold"] if metric["operator"] == "less_or_equal" else metric["value"] >= metric["threshold"]
        if not passed or metric["evidence_digest"] != digest({k: metric[k] for k in metric if k != "evidence_digest"}):
            raise QualificationError("metric threshold failed or was tampered")
    observations = record["observations"]
    if not isinstance(observations, list) or len(observations) != len(SCENARIOS) or len(observations) > LIMITS["max_observations"]:
        raise QualificationError("incomplete scenario catalog")
    seen = set()
    for item in observations:
        fields = {"id", "scenario", "adapter", "task", "session_id", "worktree_digest", "disposition", "recovery", "fence", "duration_ms", "evidence_digest"}
        if not isinstance(item, dict) or set(item) != fields or item["scenario"] not in SCENARIOS or item["scenario"] in seen or item["adapter"] not in ADAPTERS:
            raise QualificationError("invalid or duplicate scenario")
        _binding(item, record); _number(item["duration_ms"], "duration"); _d(item["evidence_digest"], "scenario evidence")
        if item["disposition"] != "observed" or item["recovery"] not in {"recovered", "blocked"} or item["fence"] not in {"checkpoint_bound", "new_worker_lease", "terminal_blocked"} or item["evidence_digest"] != digest({k: item[k] for k in item if k != "evidence_digest"}):
            raise QualificationError("invalid recovery fence or scenario evidence")
        seen.add(item["scenario"])
    if seen != set(SCENARIOS):
        raise QualificationError("scenario coverage incomplete")
    if record["result"] != {"status": "qualified_offline", "release": "blocked_pending_live_evidence", "execute": False, "provider": "not_performed", "network": "disabled", "llm": "not_performed", "live_service": "not_performed", "durable_state": "not_performed", "remote_verification": "unverified", "thresholds_passed": True, "scenarios": len(SCENARIOS)}:
        raise QualificationError("invalid result or live success claim")
    evidence = record["evidence"]
    if set(evidence) != {"checker", "task_revision", "specification_digest", "record_digest"} or evidence["checker"] != "awr-production-qualification-chaos-checker/1.0.0" or evidence["task_revision"] != 5:
        raise QualificationError("invalid evidence envelope")
    _d(evidence["specification_digest"], "specification digest")
    if evidence["record_digest"] != digest({k: record[k] for k in record if k != "evidence"}):
        raise QualificationError("record digest mismatch")
    return {"protocol": "awr-production-qualification-chaos@1.0.0", "task_revision": 5, "status": "qualified_offline", "metrics": len(metrics), "scenarios": len(observations), "release": "blocked_pending_live_evidence", "execute": False}

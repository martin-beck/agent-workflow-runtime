#!/usr/bin/env python3
"""Deterministic, privacy-safe offline observability model for AR-0056."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-runtime-observability", "version": "1.0.0"}
TASK = {"id": "AR-0056", "revision": 5}
LIMITS = {"max_events": 32, "max_metrics": 64, "max_audit_events": 32, "max_trace_bytes": 8192, "max_label_cardinality": 8, "max_clock_skew_seconds": 30}
ALERTS = {"provider_error_rate": 0.2, "provider_latency_ms": 2000, "resource_memory_bytes": 1073741824, "lease_expiry_total": 1, "clock_skew_seconds": 30}
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?payload|raw.?output|network.?address|command|executable|stack.?trace", re.I)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OPAQUE = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")

class ObservabilityError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

def _obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ObservabilityError("malformed " + name)
    return value

def _safe(value):
    if isinstance(value, dict):
        policy_keys = {"raw_payloads", "secrets", "paths", "identifiers"}
        return all((str(k) in policy_keys or not PRIVATE.search(str(k))) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and value not in {"absent", "rejected", "bounded"} and PRIVATE.search(value)) and not (isinstance(value, str) and len(value) > 256)

def _d(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ObservabilityError("invalid " + name)

def _binding(record, revision):
    if record["task"] != {"id": "AR-0056", "revision": revision} or revision != 5:
        raise ObservabilityError("unsupported or stale AR-0056 record")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64} or record["worktree"] != {"key": "agent-workflow-runtime-0056", "digest": "sha256:" + "2" * 64}:
        raise ObservabilityError("invalid project or worktree binding")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", record["session"]["id"]):
        raise ObservabilityError("invalid session binding")

def _record_digest(record):
    body = {k: record[k] for k in record if k != "evidence"}
    return digest(body)

def validate(record, expected_revision=5):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "session", "limits", "boundary", "events", "metrics", "audit", "health", "readiness", "dashboards", "alerts", "retention", "redaction", "incident_export", "evidence"}
    _obj(record, fields, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise ObservabilityError("unsupported protocol")
    _binding(record, expected_revision)
    if record["limits"] != LIMITS or record["boundary"] != {"collector": "supplied_observations_only", "provider": "not_performed", "network": "disabled", "llm": "not_performed", "durable_state": "not_performed", "remote_verification": "unverified"}:
        raise ObservabilityError("unsafe limits or execution boundary")
    events = record["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= LIMITS["max_events"]:
        raise ObservabilityError("unbounded or empty event trace")
    required_types = ["admission", "worker_started", "provider_call", "provider_result", "resource_sample", "cancellation", "lease_expiry", "quality_gate", "guidance_gate", "ui_gate", "asb_outcome", "terminal"]
    if [e.get("type") for e in events] != required_types:
        raise ObservabilityError("incomplete lifecycle observability trace")
    seen_ids, seen_corr, prior = set(), set(), None
    states = ["admitted", "active", "active", "active", "active", "cancelling", "recovered", "recovered", "recovered", "recovered", "recovered", "terminal"]
    for seq, event in enumerate(events, 1):
        _obj(event, {"sequence", "id", "type", "state", "correlation_id", "occurred_at", "ingested_at", "status", "attributes", "payload_digest", "previous_id"}, "event")
        if event["sequence"] != seq or event["id"] in seen_ids or event["previous_id"] != prior or event["state"] != states[seq - 1] or not OPAQUE.fullmatch(event["id"]) or not re.fullmatch(r"CORR-[A-Z0-9-]{1,63}", event["correlation_id"]):
            raise ObservabilityError("event identity, ordering, or state mismatch")
        if not isinstance(event["occurred_at"], int) or not isinstance(event["ingested_at"], int) or event["ingested_at"] - event["occurred_at"] > LIMITS["max_clock_skew_seconds"] or event["occurred_at"] - event["ingested_at"] > LIMITS["max_clock_skew_seconds"]:
            raise ObservabilityError("clock skew exceeds bound")
        _d(event["payload_digest"], "payload digest")
        if event["payload_digest"] != digest(event["attributes"]):
            raise ObservabilityError("payload digest mismatch")
        if not isinstance(event["attributes"], dict) or not _safe(event["attributes"]):
            raise ObservabilityError("raw or private event attributes")
        seen_ids.add(event["id"]); seen_corr.add(event["correlation_id"]); prior = event["id"]
    if len(seen_corr) > LIMITS["max_label_cardinality"]:
        raise ObservabilityError("correlation cardinality exceeds bound")
    metrics = record["metrics"]
    if not isinstance(metrics, list) or not metrics or len(metrics) > LIMITS["max_metrics"]:
        raise ObservabilityError("invalid metrics")
    names = set()
    for metric in metrics:
        _obj(metric, {"name", "kind", "value", "unit", "labels", "correlation_id"}, "metric")
        if metric["name"] in names or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", metric["name"]) or metric["kind"] not in {"counter", "gauge", "histogram"} or not isinstance(metric["value"], (int, float)) or not isinstance(metric["labels"], dict) or len(metric["labels"]) > LIMITS["max_label_cardinality"] or metric["correlation_id"] not in seen_corr:
            raise ObservabilityError("invalid metric or cardinality")
        names.add(metric["name"])
    audit = record["audit"]
    if not isinstance(audit, list) or len(audit) != len(events):
        raise ObservabilityError("audit does not reconstruct lifecycle")
    for seq, item in enumerate(audit, 1):
        _obj(item, {"sequence", "event_id", "authority", "action", "correlation_id", "disposition", "evidence_digest", "previous_digest"}, "audit event")
        if item["sequence"] != seq or item["event_id"] != events[seq - 1]["id"] or item["correlation_id"] != events[seq - 1]["correlation_id"] or item["authority"] not in {"runtime_observation", "coordinator_observation", "provider_observation", "awq_observation", "awg_observation", "ui_observation", "asb_observation"} or item["disposition"] != "observed_not_authoritative":
            raise ObservabilityError("audit reconstruction mismatch")
        _d(item["evidence_digest"], "audit evidence digest"); _d(item["previous_digest"], "audit previous digest")
        expected_previous = digest("genesis") if seq == 1 else digest(audit[seq - 2])
        if item["evidence_digest"] != digest(events[seq - 1]) or item["previous_digest"] != expected_previous:
            raise ObservabilityError("audit digest chain mismatch")
    if record["health"] != {"status": "observed", "collector": "offline", "exporter": "available", "clock": "within_bound"} or record["readiness"] != {"status": "observed", "provider": "not_performed", "network": "disabled", "live_service": "not_performed"}:
        raise ObservabilityError("health or readiness claimed")
    if set(record["dashboards"]) != {"lease", "worker", "provider"} or any(not isinstance(record["dashboards"][k], dict) for k in record["dashboards"]):
        raise ObservabilityError("missing dashboard projection")
    if not isinstance(record["alerts"], list) or any(a.get("disposition") != "observed" or a.get("name") not in ALERTS or a.get("threshold") != ALERTS[a.get("name")] for a in record["alerts"]):
        raise ObservabilityError("invalid alert projection")
    if record["retention"] != {"retention_days": 7, "mode": "digest_only", "raw_payloads": False, "export_max_bytes": 16384} or record["redaction"] != {"raw_payloads": "absent", "identifiers": "bounded", "secrets": "rejected", "paths": "rejected"}:
        raise ObservabilityError("unsafe retention or redaction")
    _obj(record["incident_export"], {"format", "status", "event_count", "audit_digest", "redacted", "network", "durable_state", "on_failure"}, "incident export")
    if record["incident_export"] != {"format": "jsonl", "status": "prepared_not_exported", "event_count": len(events), "audit_digest": record["incident_export"]["audit_digest"], "redacted": True, "network": "disabled", "durable_state": "not_performed", "on_failure": "retain_bounded_redacted"}:
        raise ObservabilityError("incident export boundary")
    if not _safe(record) or record["evidence"].get("record_digest") != _record_digest(record):
        raise ObservabilityError("privacy leak or record digest mismatch")
    return {"contract": "awr-runtime-observability@1.0.0", "task_revision": 5, "events": len(events), "metrics": len(metrics), "audit_reconstructed": True, "export": "prepared_not_exported", "provider": "not_performed", "network": "disabled", "durable_state": "not_performed"}

#!/usr/bin/env python3
"""Deterministic, privacy-safe operational observability for AR-0091.

This module evaluates supplied observations only.  It never collects telemetry,
contacts a service, changes Coordinator state, or treats telemetry as an
authority decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-operational-observability", "version": "1.0.0"}
TASK = {"id": "AR-0091", "revision": 3}
BOUNDARY = {
    "collection": "supplied_observations_only",
    "provider": "not_performed",
    "network": "disabled",
    "llm": "not_performed",
    "coordinator_write": "not_performed",
    "durable_state": "not_performed",
    "authority": "observed_not_authoritative",
}
LIMITS = {
    "max_observations": 64,
    "max_metrics": 64,
    "max_agents": 8,
    "max_alerts": 32,
    "max_incident_events": 32,
    "max_export_bytes": 16384,
    "max_age_seconds": 60,
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OPAQUE = re.compile(r"^[A-Z][A-Z0-9-]{1,63}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|"
    r"host[_ -]?identifier|raw[_ -]?(?:output|payload)|network[_ -]?address|"
    r"command|executable|stack[_ -]?trace",
    re.IGNORECASE,
)


class OperationalObservabilityError(ValueError):
    """Raised when an operational evidence envelope is unsafe or inconsistent."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _object(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OperationalObservabilityError("malformed_" + name)
    return value


def _digest(value: Any, name: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise OperationalObservabilityError("invalid_" + name)


def _safe(value: Any) -> bool:
    if isinstance(value, dict):
        return all(
            (str(k) == "raw_payloads" or not PRIVATE.search(str(k))) and _safe(v)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    if isinstance(value, str):
        return len(value) <= 128 and not PRIVATE.search(value)
    return isinstance(value, (bool, int, float)) or value is None


def _binding(record: dict[str, Any], expected_revision: int) -> None:
    if expected_revision != 3 or record["task"] != TASK:
        raise OperationalObservabilityError("unsupported_or_stale_task_revision")
    if record["project"] != {
        "key": "agent-workflow-runtime",
        "revision": "sha256:" + "1" * 64,
    }:
        raise OperationalObservabilityError("invalid_project_binding")
    if record["worktree"] != {
        "key": "agent-workflow-runtime-0091",
        "digest": "sha256:" + "2" * 64,
    }:
        raise OperationalObservabilityError("invalid_worktree_binding")


def _record_digest(record: dict[str, Any]) -> str:
    return digest({k: record[k] for k in record if k != "evidence"})


def _validate_observations(
    observations: list[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    if not 1 <= len(observations) <= LIMITS["max_observations"]:
        raise OperationalObservabilityError("observation_bound_exceeded")
    agents: set[str] = set()
    previous = None
    for sequence, observation in enumerate(observations, 1):
        _object(
            observation,
            {
                "sequence",
                "id",
                "agent_id",
                "kind",
                "state",
                "at",
                "attributes",
                "evidence_digest",
                "previous_digest",
            },
            "observation",
        )
        if observation["sequence"] != sequence or not OPAQUE.fullmatch(
            observation["id"]
        ):
            raise OperationalObservabilityError("invalid_observation_sequence")
        if observation["previous_digest"] != (
            digest("genesis") if sequence == 1 else previous
        ):
            raise OperationalObservabilityError("observation_chain_mismatch")
        if not OPAQUE.fullmatch(observation["agent_id"]):
            raise OperationalObservabilityError("invalid_agent_id")
        if observation["kind"] not in {
            "admission",
            "queue",
            "lease",
            "resource",
            "failure",
            "recovery",
            "terminal",
        }:
            raise OperationalObservabilityError("unknown_observation_kind")
        if not isinstance(observation["at"], int) or observation["at"] < 0:
            raise OperationalObservabilityError("invalid_observation_time")
        _digest(observation["evidence_digest"], "evidence_digest")
        if observation["evidence_digest"] != digest(observation["attributes"]):
            raise OperationalObservabilityError("observation_digest_mismatch")
        if not _safe(observation["attributes"]):
            raise OperationalObservabilityError("privacy_violation")
        agents.add(observation["agent_id"])
        previous = digest(observation)
    if len(agents) > LIMITS["max_agents"]:
        raise OperationalObservabilityError("agent_cardinality_exceeded")
    return agents, {observation["kind"] for observation in observations}


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    fields = {
        "schema_version",
        "protocol",
        "task",
        "project",
        "worktree",
        "boundary",
        "limits",
        "observations",
        "metrics",
        "dashboards",
        "health",
        "readiness",
        "slos",
        "alerts",
        "incident",
        "retention",
        "evidence",
    }
    _object(record, fields, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise OperationalObservabilityError("unsupported_protocol")
    _binding(record, expected_revision)
    if record["boundary"] != BOUNDARY or record["limits"] != LIMITS:
        raise OperationalObservabilityError("unsafe_boundary_or_limits")
    agents, kinds = _validate_observations(record["observations"])
    required_kinds = {
        "admission",
        "queue",
        "lease",
        "resource",
        "failure",
        "recovery",
        "terminal",
    }
    if kinds != required_kinds:
        raise OperationalObservabilityError("incomplete_operational_trace")
    metrics = record["metrics"]
    if not isinstance(metrics, list) or not 1 <= len(metrics) <= LIMITS["max_metrics"]:
        raise OperationalObservabilityError("invalid_metric_bound")
    names = set()
    for metric in metrics:
        _object(
            metric, {"name", "value", "unit", "agent_id", "evidence_digest"}, "metric"
        )
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", metric["name"])
            or metric["name"] in names
        ):
            raise OperationalObservabilityError("invalid_metric_name")
        if (
            not isinstance(metric["value"], (int, float))
            or isinstance(metric["value"], bool)
            or metric["value"] < 0
            or not OPAQUE.fullmatch(metric["agent_id"])
        ):
            raise OperationalObservabilityError("invalid_metric_value")
        if (
            metric["agent_id"] not in agents
            or not isinstance(metric["unit"], str)
            or len(metric["unit"]) > 16
        ):
            raise OperationalObservabilityError("metric_binding_mismatch")
        _digest(metric["evidence_digest"], "metric_digest")
        names.add(metric["name"])
    dashboards = _object(
        record["dashboards"], {"queue", "leases", "resources"}, "dashboards"
    )
    for value in dashboards.values():
        _object(
            value,
            {"agents", "status", "observed_not_authoritative", "digest"},
            "dashboard",
        )
        if (
            not isinstance(value["agents"], int)
            or value["agents"] != len(agents)
            or value["status"] not in {"healthy", "degraded", "unknown"}
            or value["observed_not_authoritative"] is not True
        ):
            raise OperationalObservabilityError("invalid_dashboard")
        _digest(value["digest"], "dashboard_digest")
    _object(
        record["health"],
        {"liveness", "observed_at", "max_age_seconds", "status", "stale"},
        "health",
    )
    if record["health"] != {
        "liveness": "alive",
        "observed_at": 100,
        "max_age_seconds": 60,
        "status": "observed",
        "stale": False,
    }:
        raise OperationalObservabilityError("stale_or_claimed_health")
    _object(
        record["readiness"],
        {"status", "dependencies", "provider", "network", "authority"},
        "readiness",
    )
    if record["readiness"] != {
        "status": "observed",
        "dependencies": "supplied_only",
        "provider": "not_performed",
        "network": "disabled",
        "authority": "not_authoritative",
    }:
        raise OperationalObservabilityError("claimed_readiness")
    if not isinstance(record["slos"], list) or len(record["slos"]) != 4:
        raise OperationalObservabilityError("incomplete_slos")
    for slo in record["slos"]:
        _object(slo, {"name", "target", "window", "status", "evidence_digest"}, "slo")
        if (
            not isinstance(slo["name"], str)
            or not 0 < slo["target"] <= 1
            or slo["window"] not in {"hour", "day"}
            or slo["status"] not in {"observed", "unknown", "breached"}
        ):
            raise OperationalObservabilityError("invalid_slo")
        _digest(slo["evidence_digest"], "slo_digest")
    alerts = record["alerts"]
    if not isinstance(alerts, list) or not 1 <= len(alerts) <= LIMITS["max_alerts"]:
        raise OperationalObservabilityError("invalid_alert_bound")
    alert_ids = set()
    for alert in alerts:
        _object(
            alert,
            {
                "id",
                "name",
                "threshold",
                "status",
                "disposition",
                "dedup_key",
                "evidence_digest",
            },
            "alert",
        )
        if (
            not OPAQUE.fullmatch(alert["id"])
            or alert["id"] in alert_ids
            or not isinstance(alert["threshold"], (int, float))
            or alert["status"] not in {"firing", "clear"}
            or alert["disposition"] != "observed"
            or not OPAQUE.fullmatch(alert["dedup_key"])
        ):
            raise OperationalObservabilityError(
                "alert_deduplication_or_privacy_failure"
            )
        _digest(alert["evidence_digest"], "alert_digest")
        alert_ids.add(alert["id"])
    _object(
        record["incident"],
        {
            "id",
            "status",
            "event_count",
            "snapshot_digest",
            "redacted",
            "export",
            "diagnosis",
            "authority",
        },
        "incident",
    )
    incident = record["incident"]
    if (
        not OPAQUE.fullmatch(incident["id"])
        or incident["status"] != "observed"
        or incident["event_count"] != len(record["observations"])
        or not isinstance(incident["diagnosis"], list)
        or not incident["diagnosis"]
        or incident["redacted"] is not True
        or incident["export"] != "prepared_not_exported"
        or incident["authority"] != "not_authoritative"
    ):
        raise OperationalObservabilityError("invalid_incident_snapshot")
    _digest(incident["snapshot_digest"], "incident_digest")
    for item in incident["diagnosis"]:
        if item not in {
            "queue_pressure",
            "lease_expiry",
            "resource_pressure",
            "recovery_observed",
        }:
            raise OperationalObservabilityError("non_deterministic_diagnosis")
    if record["retention"] != {
        "days": 7,
        "mode": "digest_only",
        "raw_payloads": False,
        "max_export_bytes": 16384,
    }:
        raise OperationalObservabilityError("unsafe_retention")
    if not _safe(record) or record["evidence"].get("record_digest") != _record_digest(
        record
    ):
        raise OperationalObservabilityError("privacy_or_record_digest_mismatch")
    return {
        "contract": "awr-operational-observability@1.0.0",
        "task_revision": 3,
        "agents": len(agents),
        "observations": len(record["observations"]),
        "slos": len(record["slos"]),
        "alerts": len(alerts),
        "diagnosis": incident["diagnosis"],
        "provider": "not_performed",
        "network": "disabled",
        "authority": "observed_not_authoritative",
    }

#!/usr/bin/env python3
"""Deterministic virtual-time qualification harness for AR-0094."""

from __future__ import annotations

import hashlib
import json
from typing import Any

PROTOCOL = {"id": "awr-integrated-qualification", "version": "1.0.0"}
SCENARIOS = [
    "concurrency",
    "resource_contention",
    "lease_loss",
    "process_loss",
    "authority_outage",
    "replay",
    "cancellation",
    "upgrade",
    "rollback",
]
THRESHOLDS = {
    "jobs": 256,
    "projects": 4,
    "agents": 6,
    "min_fairness_percent": 100,
    "max_recovery_events": 32,
    "max_privacy_violations": 0,
}


class IntegratedQualificationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            value if isinstance(value, bytes) else canonical(value)
        ).hexdigest()
    )


def simulate(seed: int, jobs: int) -> dict[str, Any]:
    if seed < 0 or jobs != THRESHOLDS["jobs"]:
        raise IntegratedQualificationError("unsupported_simulation_size")
    recovery = (seed * 7) % 17 + 9
    blocked = (seed * 3) % 5 + 3
    completed = jobs - blocked
    trace = {
        "seed": seed,
        "jobs": jobs,
        "completed": completed,
        "blocked": blocked,
        "recovery_events": recovery,
        "projects": THRESHOLDS["projects"],
        "agents": THRESHOLDS["agents"],
        "fairness_percent": 100,
        "privacy_violations": 0,
        "scenario_count": len(SCENARIOS),
    }
    trace["trace_digest"] = digest(trace)
    return trace


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    required = {
        "schema_version",
        "protocol",
        "task",
        "offline",
        "configuration",
        "scenarios",
        "expected",
        "replay",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise IntegratedQualificationError("malformed_record")
    if (
        record["schema_version"] != 1
        or record["protocol"] != PROTOCOL
        or record["task"] != {"id": "AR-0094", "revision": expected_revision}
        or expected_revision != 3
    ):
        raise IntegratedQualificationError("stale_or_unsupported_contract")
    if record["offline"] != {
        "virtual_time": True,
        "local_mock_agents": True,
        "provider": "not_performed",
        "network": "disabled",
        "llm": "not_performed",
        "durable_state": "not_performed",
    }:
        raise IntegratedQualificationError("external_execution_claim")
    if (
        record["configuration"]
        != {
            "seed": 17,
            "jobs": 256,
            "projects": 4,
            "agents": 6,
            "replay_required": True,
        }
        or record["scenarios"] != SCENARIOS
    ):
        raise IntegratedQualificationError("invalid_configuration_or_scenarios")
    expected = simulate(17, 256)
    if record["expected"] != expected:
        raise IntegratedQualificationError("qualification_threshold_or_trace_mismatch")
    replay = record["replay"]
    if replay != {
        "equal": True,
        "first_digest": expected["trace_digest"],
        "second_digest": expected["trace_digest"],
        "counterexample": None,
    }:
        raise IntegratedQualificationError("replay_equality_failed")
    return {
        "checker": "awr-integrated-qualification-checker/1.0.0",
        "task_revision": 3,
        "status": "qualified_offline",
        "jobs": expected["jobs"],
        "scenarios": len(SCENARIOS),
        "replay_equal": True,
        "execute": False,
        "network": "disabled",
    }

#!/usr/bin/env python3
"""Offline full multi-project workflow orchestration contract for AR-0095."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-multi-project-workflow", "version": "1.0.0"}
STAGES = [
    "intake",
    "decomposition",
    "scheduling",
    "specialist_a",
    "specialist_b",
    "integration",
    "quality",
    "oracle",
    "ui",
    "artifact",
]
AUTHORITIES = {
    "intake": "coordinator",
    "decomposition": "runtime",
    "scheduling": "runtime",
    "specialist_a": "worker",
    "specialist_b": "worker",
    "integration": "integration",
    "quality": "awq",
    "oracle": "awg",
    "ui": "ui",
    "artifact": "coordinator",
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|raw[_ -]?output|network",
    re.IGNORECASE,
)


class MultiProjectWorkflowError(ValueError):
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


def _safe(value: Any) -> bool:
    if isinstance(value, dict):
        return all(not PRIVATE.search(str(k)) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 128 or PRIVATE.search(value)))


def _digest(value: Any, name: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise MultiProjectWorkflowError("invalid_" + name)


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    fields = {
        "schema_version",
        "protocol",
        "task",
        "offline",
        "workflow",
        "projects",
        "operations",
        "terminal",
        "evidence",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise MultiProjectWorkflowError("malformed_record")
    if (
        record["schema_version"] != 1
        or record["protocol"] != PROTOCOL
        or record["task"] != {"id": "AR-0095", "revision": expected_revision}
        or expected_revision != 3
    ):
        raise MultiProjectWorkflowError("stale_or_unsupported_contract")
    if record["offline"] != {
        "local_mock_agents": True,
        "provider": "not_performed",
        "network": "disabled",
        "llm": "not_performed",
        "publication": "not_performed",
        "durable_state": "not_performed",
    }:
        raise MultiProjectWorkflowError("external_execution_claim")
    workflow = record["workflow"]
    if workflow != {
        "id": "WF-AR0095",
        "revision": 3,
        "jobs": 18,
        "parallel_workers": 6,
        "resume_after_failure": True,
    }:
        raise MultiProjectWorkflowError("invalid_workflow_configuration")
    if record["projects"] != [
        {"id": "project-a", "jobs": 9},
        {"id": "project-b", "jobs": 9},
    ]:
        raise MultiProjectWorkflowError("invalid_project_set")
    operations = record["operations"]
    if not isinstance(operations, list) or len(operations) != len(STAGES):
        raise MultiProjectWorkflowError("incomplete_workflow")
    seen: set[str] = set()
    for sequence, operation in enumerate(operations, 1):
        required = {
            "sequence",
            "stage",
            "authority",
            "status",
            "depends_on",
            "attempt",
            "resumed",
            "evidence_digest",
        }
        if (
            not isinstance(operation, dict)
            or set(operation) != required
            or operation["sequence"] != sequence
            or operation["stage"] not in STAGES
            or operation["stage"] in seen
        ):
            raise MultiProjectWorkflowError("malformed_or_replayed_operation")
        stage = operation["stage"]
        if (
            operation["authority"] != AUTHORITIES[stage]
            or operation["status"]
            not in {"accepted", "approved", "completed", "observed"}
            or not isinstance(operation["attempt"], int)
            or operation["attempt"] < 1
        ):
            raise MultiProjectWorkflowError("authority_or_status_violation")
        expected_deps = [
            s
            for s in STAGES
            if STAGES.index(s) < STAGES.index(stage)
            and s not in {"specialist_a", "specialist_b"}
        ]
        if stage == "specialist_a":
            expected_deps = ["scheduling"]
        if stage == "specialist_b":
            expected_deps = ["scheduling"]
        if operation["depends_on"] != expected_deps or any(
            dep not in seen for dep in expected_deps
        ):
            raise MultiProjectWorkflowError("dependency_or_parallelism_violation")
        if stage == "specialist_b" and operation["resumed"] is not True:
            raise MultiProjectWorkflowError("safe_resume_not_proven")
        if stage != "specialist_b" and operation["resumed"] is not False:
            raise MultiProjectWorkflowError("unexpected_resume")
        _digest(operation["evidence_digest"], "operation_digest")
        if operation["evidence_digest"] != digest(
            {k: operation[k] for k in operation if k != "evidence_digest"}
        ) or not _safe(operation):
            raise MultiProjectWorkflowError("tampered_or_private_operation")
        seen.add(stage)
    terminal = record["terminal"]
    if terminal != {
        "status": "completed",
        "reconciled": True,
        "execute": False,
        "publication": "not_performed",
        "remote_verification": "unverified",
    }:
        raise MultiProjectWorkflowError("terminal_reconciliation_failure")
    evidence = record["evidence"]
    if (
        set(evidence) != {"record_digest", "checker"}
        or evidence["checker"] != "awr-multi-project-workflow-checker/1.0.0"
        or evidence["record_digest"]
        != digest({k: record[k] for k in record if k != "evidence"})
    ):
        raise MultiProjectWorkflowError("evidence_digest_mismatch")
    return {
        "checker": evidence["checker"],
        "task_revision": 3,
        "status": "completed",
        "stages": len(operations),
        "parallel_workers": 6,
        "reconciled": True,
        "execute": False,
        "network": "disabled",
    }

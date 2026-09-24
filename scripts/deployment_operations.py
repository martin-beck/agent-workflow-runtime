#!/usr/bin/env python3
"""Offline, deterministic deployment and rollback contract for AR-0093."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-deployment-operations", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|raw[_ -]?output|command|network",
    re.IGNORECASE,
)
SAFE_ENUMS = {
    "network",
    "provider",
    "publication",
    "not_performed",
    "disabled",
    "supplied_target",
}


class DeploymentOperationsError(ValueError):
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


def _object(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DeploymentOperationsError("malformed_" + name)
    return value


def _digest(value: Any, name: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise DeploymentOperationsError("invalid_" + name)


def _safe(value: Any) -> bool:
    if isinstance(value, dict):
        return all(
            (str(k) in SAFE_ENUMS or not PRIVATE.search(str(k))) and _safe(v)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (
        isinstance(value, str)
        and (len(value) > 128 or (PRIVATE.search(value) and value not in SAFE_ENUMS))
    )


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    fields = {
        "schema_version",
        "protocol",
        "task",
        "artifact",
        "compatibility",
        "migration",
        "rollout",
        "rollback",
        "health",
        "provenance",
        "evidence",
        "offline",
    }
    _object(record, fields, "record")
    if (
        record["schema_version"] != 1
        or record["protocol"] != PROTOCOL
        or record["task"] != {"id": "AR-0093", "revision": expected_revision}
        or expected_revision != 3
    ):
        raise DeploymentOperationsError("stale_or_unsupported_contract")
    if record["offline"] != {
        "package": "not_performed",
        "deployment": "not_performed",
        "publication": "not_performed",
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
    }:
        raise DeploymentOperationsError("external_execution_claim")
    artifact = _object(
        record["artifact"],
        {"status", "name", "version", "source_digest", "artifact_digest", "format"},
        "artifact",
    )
    if (
        artifact["status"] != "verified"
        or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", artifact["name"])
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", artifact["version"])
        or artifact["format"] not in {"tar", "wheel", "container"}
    ):
        raise DeploymentOperationsError("artifact_not_reproducible")
    _digest(artifact["source_digest"], "source_digest")
    _digest(artifact["artifact_digest"], "artifact_digest")
    if artifact["source_digest"] == artifact["artifact_digest"]:
        raise DeploymentOperationsError("source_artifact_digest_collision")
    compatibility = _object(
        record["compatibility"],
        {"status", "runtime_digest", "platform_digest", "contracts"},
        "compatibility",
    )
    if (
        compatibility["status"] != "compatible"
        or not isinstance(compatibility["contracts"], list)
        or not compatibility["contracts"]
    ):
        raise DeploymentOperationsError("incompatible_runtime")
    _digest(compatibility["runtime_digest"], "runtime_digest")
    _digest(compatibility["platform_digest"], "platform_digest")
    for contract in compatibility["contracts"]:
        item = _object(contract, {"id", "version", "digest", "mode"}, "contract")
        if (
            item["mode"] != "exact"
            or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", item["id"])
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", item["version"])
        ):
            raise DeploymentOperationsError("non_exact_contract")
        _digest(item["digest"], "contract_digest")
    migration = _object(
        record["migration"],
        {
            "status",
            "from_version",
            "to_version",
            "config_digest",
            "reversible",
            "interruption_recovery",
        },
        "migration",
    )
    if (
        migration["status"] != "prepared"
        or migration["from_version"] == migration["to_version"]
        or migration["reversible"] is not True
        or migration["interruption_recovery"] != "checkpoint_required"
    ):
        raise DeploymentOperationsError("unsafe_migration")
    _digest(migration["config_digest"], "config_digest")
    rollout = _object(
        record["rollout"],
        {"status", "strategy", "execute", "health_gate", "target", "network"},
        "rollout",
    )
    if rollout != {
        "status": "prepared",
        "strategy": "canary",
        "execute": False,
        "health_gate": "supplied_observation",
        "target": "supplied_target",
        "network": "disabled",
    }:
        raise DeploymentOperationsError("rollout_exceeds_offline_boundary")
    rollback = _object(
        record["rollback"],
        {
            "status",
            "target_version",
            "target_digest",
            "execute",
            "exact_target",
            "durable_state",
        },
        "rollback",
    )
    if rollback != {
        "status": "ready",
        "target_version": migration["from_version"],
        "target_digest": artifact["source_digest"],
        "execute": False,
        "exact_target": True,
        "durable_state": "not_performed",
    }:
        raise DeploymentOperationsError("rollback_not_exact")
    health = _object(
        record["health"],
        {"status", "liveness", "readiness", "stale", "evidence_digest"},
        "health",
    )
    if (
        health["status"] != "observed"
        or health["liveness"] != "alive"
        or health["readiness"] != "ready"
        or health["stale"] is not False
    ):
        raise DeploymentOperationsError("health_gate_not_passed")
    _digest(health["evidence_digest"], "health_digest")
    provenance = _object(
        record["provenance"],
        {"status", "source_digest", "artifact_digest", "release_digest", "publication"},
        "provenance",
    )
    if provenance != {
        "status": "complete",
        "source_digest": artifact["source_digest"],
        "artifact_digest": artifact["artifact_digest"],
        "release_digest": provenance["release_digest"],
        "publication": "not_performed",
    }:
        raise DeploymentOperationsError("incomplete_provenance")
    _digest(provenance["release_digest"], "release_digest")
    evidence = _object(record["evidence"], {"record_digest", "checker"}, "evidence")
    _digest(evidence["record_digest"], "record_digest")
    if evidence["checker"] != "awr-deployment-operations-checker/1.0.0" or evidence[
        "record_digest"
    ] != digest({k: record[k] for k in record if k != "evidence"}):
        raise DeploymentOperationsError("evidence_digest_mismatch")
    if not _safe(record):
        raise DeploymentOperationsError("privacy_violation")
    return {
        "checker": evidence["checker"],
        "task_revision": 3,
        "status": "qualified",
        "rollout": "prepared",
        "rollback": "ready",
        "execute": False,
        "network": "disabled",
        "publication": "not_performed",
    }

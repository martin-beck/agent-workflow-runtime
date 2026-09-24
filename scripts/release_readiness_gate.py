#!/usr/bin/env python3
"""Offline production-readiness gate for AR-0096."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-release-readiness-gate", "version": "1.0.0"}
SECTIONS = [
    "security",
    "compatibility",
    "capacity",
    "slos",
    "recovery",
    "observability",
    "deployment",
    "support",
    "incident",
    "rollback",
    "documentation",
    "residual_risk",
]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|raw[_ -]?output|network",
    re.IGNORECASE,
)
SAFE_ENUMS = {
    "network",
    "provider",
    "publication",
    "not_performed",
    "disabled",
    "runtime-operations",
    "unverified",
}


class ReleaseReadinessError(ValueError):
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


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    fields = {
        "schema_version",
        "protocol",
        "task",
        "offline",
        "release",
        "sections",
        "staged",
        "evidence",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise ReleaseReadinessError("malformed_record")
    if (
        record["schema_version"] != 1
        or record["protocol"] != PROTOCOL
        or record["task"] != {"id": "AR-0096", "revision": expected_revision}
        or expected_revision != 3
    ):
        raise ReleaseReadinessError("stale_or_unsupported_contract")
    if record["offline"] != {
        "local_mock_agents": True,
        "provider": "not_performed",
        "network": "disabled",
        "llm": "not_performed",
        "publication": "not_performed",
        "durable_state": "not_performed",
    }:
        raise ReleaseReadinessError("external_execution_claim")
    if record["release"] != {
        "status": "qualified",
        "owner": "runtime-operations",
        "rollback_owner": "runtime-operations",
        "live_release": "not_performed",
        "remote_verification": "unverified",
    }:
        raise ReleaseReadinessError("release_ownership_or_boundary_failure")
    sections = record["sections"]
    if not isinstance(sections, list) or len(sections) != len(SECTIONS):
        raise ReleaseReadinessError("incomplete_readiness_sections")
    seen = set()
    for section in sections:
        if (
            not isinstance(section, dict)
            or set(section) != {"name", "status", "checks", "evidence_digest"}
            or section["name"] not in SECTIONS
            or section["name"] in seen
        ):
            raise ReleaseReadinessError("malformed_or_replayed_section")
        if (
            section["status"]
            != ("prepared" if section["name"] == "rollback" else "qualified")
            or not isinstance(section["checks"], list)
            or not section["checks"]
            or any(
                not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", check)
                for check in section["checks"]
            )
        ):
            raise ReleaseReadinessError("section_not_qualified")
        if not isinstance(section["evidence_digest"], str) or not DIGEST.fullmatch(
            section["evidence_digest"]
        ):
            raise ReleaseReadinessError("invalid_section_digest")
        if section["evidence_digest"] != digest(
            {k: section[k] for k in section if k != "evidence_digest"}
        ):
            raise ReleaseReadinessError("section_digest_mismatch")
        seen.add(section["name"])
    if record["staged"] != {
        "canary": "qualified",
        "load": "qualified",
        "upgrade": "qualified",
        "rollback": "prepared",
        "execute": False,
        "mock_agents": True,
    }:
        raise ReleaseReadinessError("staged_gate_failure")
    evidence = record["evidence"]
    if (
        set(evidence) != {"record_digest", "checker"}
        or evidence["checker"] != "awr-release-readiness-checker/1.0.0"
        or evidence["record_digest"]
        != digest({k: record[k] for k in record if k != "evidence"})
    ):
        raise ReleaseReadinessError("evidence_digest_mismatch")
    if not _safe(record):
        raise ReleaseReadinessError("privacy_violation")
    return {
        "checker": evidence["checker"],
        "task_revision": 3,
        "status": "qualified",
        "sections": len(sections),
        "rollback": "prepared",
        "execute": False,
        "network": "disabled",
        "provider": "not_performed",
    }


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

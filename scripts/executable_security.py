#!/usr/bin/env python3
"""Fail-closed, offline executable security contract for AR-0092."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-executable-security", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|raw[_ -]?output|network[_ -]?address",
    re.IGNORECASE,
)
SAFE_ENUMS = {
    "network",
    "credentials",
    "provider",
    "llm",
    "publication",
    "not_performed",
    "disabled",
    "clear",
}


class ExecutableSecurityError(ValueError):
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
        raise ExecutableSecurityError("malformed_" + name)
    return value


def _digest(value: Any, name: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ExecutableSecurityError("invalid_" + name)


def _safe(value: Any) -> bool:
    if isinstance(value, dict):
        return all(
            (str(k) == "secret_refs" or not PRIVATE.search(str(k))) and _safe(v)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (
        isinstance(value, str)
        and (
            len(value) > 128
            or (
                PRIVATE.search(value)
                and value not in SAFE_ENUMS
                and not value.startswith("secret-ref:")
            )
        )
    )


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    fields = {
        "schema_version",
        "protocol",
        "task",
        "artifact",
        "dependency",
        "sbom",
        "secret_refs",
        "privilege",
        "egress",
        "sandbox",
        "redaction",
        "rotation",
        "containment",
        "evidence",
        "offline",
    }
    _object(record, fields, "record")
    if (
        record["schema_version"] != 1
        or record["protocol"] != PROTOCOL
        or record["task"] != {"id": "AR-0092", "revision": expected_revision}
        or expected_revision != 3
    ):
        raise ExecutableSecurityError("stale_or_unsupported_contract")
    if record["offline"] != {
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
        "scanner": "supplied_observations_only",
        "mutation": "not_performed",
    }:
        raise ExecutableSecurityError("external_execution_claim")
    artifact = _object(
        record["artifact"],
        {
            "status",
            "digest",
            "provenance_digest",
            "signature_digest",
            "dco",
            "verified",
        },
        "artifact",
    )
    if (
        artifact["status"] != "verified"
        or artifact["dco"] != "signed"
        or artifact["verified"] is not True
    ):
        raise ExecutableSecurityError("artifact_not_verified")
    for key in ("digest", "provenance_digest", "signature_digest"):
        _digest(artifact[key], key)
    dependency = _object(
        record["dependency"],
        {
            "status",
            "manifest_digest",
            "lock_digest",
            "pinned",
            "license_digest",
            "vulnerability_status",
        },
        "dependency",
    )
    if (
        dependency["status"] != "verified"
        or dependency["pinned"] is not True
        or dependency["vulnerability_status"] not in {"clear", "triaged"}
    ):
        raise ExecutableSecurityError("dependency_not_verified")
    for key in ("manifest_digest", "lock_digest", "license_digest"):
        _digest(dependency[key], key)
    sbom = _object(record["sbom"], {"status", "format", "digest", "complete"}, "sbom")
    if (
        sbom["status"] != "verified"
        or sbom["format"] != "spdx-json"
        or sbom["complete"] is not True
    ):
        raise ExecutableSecurityError("sbom_not_verified")
    _digest(sbom["digest"], "sbom_digest")
    secret_refs = _object(
        record["secret_refs"],
        {"status", "values_absent", "references", "rotation_required"},
        "secret_refs",
    )
    if secret_refs != {
        "status": "pass",
        "values_absent": True,
        "references": ["secret-ref:fixture"],
        "rotation_required": False,
    }:
        raise ExecutableSecurityError("secret_reference_violation")
    privilege = _object(
        record["privilege"], {"status", "granted", "denied", "elevation"}, "privilege"
    )
    if privilege != {
        "status": "pass",
        "granted": ["read", "edit", "test"],
        "denied": ["network", "credentials", "provider", "llm", "publication"],
        "elevation": "none",
    }:
        raise ExecutableSecurityError("least_privilege_violation")
    for name, expected in (
        (
            "egress",
            {
                "status": "pass",
                "network": "disabled",
                "allowlist": [],
                "fallback": "deny",
            },
        ),
        (
            "sandbox",
            {
                "status": "pass",
                "filesystem": "workspace_only",
                "process": "bounded",
                "fallback": "deny",
            },
        ),
        (
            "redaction",
            {
                "status": "pass",
                "raw_content_absent": True,
                "private_values_absent": True,
                "digest_only": True,
            },
        ),
        (
            "rotation",
            {
                "status": "pass",
                "old_key": "revocable",
                "new_key": "prepared",
                "overlap": "bounded",
            },
        ),
        (
            "containment",
            {
                "status": "pass",
                "on_failure": "stop_preserve_digest_only_escalate",
                "recovery": "requires_requalification",
            },
        ),
    ):
        if _object(record[name], set(expected), name) != expected:
            raise ExecutableSecurityError(name + "_fail_open")
    evidence = _object(
        record["evidence"],
        {"record_digest", "artifact_digest", "dependency_digest"},
        "evidence",
    )
    for key in evidence:
        _digest(evidence[key], key)
    if not _safe(record):
        raise ExecutableSecurityError("privacy_violation")
    if evidence["record_digest"] != digest(
        {k: record[k] for k in record if k != "evidence"}
    ):
        raise ExecutableSecurityError("record_digest_mismatch")
    return {
        "checker": "awr-executable-security-checker/1.0.0",
        "task_revision": 3,
        "status": "pass",
        "network": "disabled",
        "provider": "not_performed",
        "fail_closed": True,
    }

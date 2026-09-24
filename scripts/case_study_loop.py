#!/usr/bin/env python3
"""Privacy-safe, proposal-only case-study analysis for AR-0097."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-case-study-loop", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(
    r"credential|password|secret|token|prompt|transcript|private[_ -]?path|raw[_ -]?output|network",
    re.IGNORECASE,
)
SAFE_ENUMS = {"network", "provider", "not_performed", "disabled", "approval"}
KINDS = {"outcome", "failure", "intervention", "bottleneck", "improvement_proposal"}


class CaseStudyError(ValueError):
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


def _d(value: Any, name: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise CaseStudyError("invalid_" + name)


def validate(record: dict[str, Any], expected_revision: int = 3) -> dict[str, Any]:
    fields = {
        "schema_version",
        "protocol",
        "task",
        "offline",
        "cycles",
        "findings",
        "analysis",
        "evidence",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise CaseStudyError("malformed_record")
    if (
        record["schema_version"] != 1
        or record["protocol"] != PROTOCOL
        or record["task"] != {"id": "AR-0097", "revision": expected_revision}
        or expected_revision != 3
    ):
        raise CaseStudyError("stale_or_unsupported_contract")
    if record["offline"] != {
        "raw_content": False,
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
        "policy_mutation": "not_performed",
        "approval": "not_performed",
    }:
        raise CaseStudyError("external_execution_or_policy_claim")
    cycles = record["cycles"]
    if not isinstance(cycles, list) or len(cycles) < 2:
        raise CaseStudyError("need_two_cycles")
    ids = set()
    for cycle in cycles:
        required = {
            "id",
            "project_digest",
            "task_revision",
            "autonomy",
            "roles",
            "concurrency",
            "interventions",
            "blocked",
            "retries",
            "terminal",
            "evidence_digest",
        }
        if (
            not isinstance(cycle, dict)
            or set(cycle) != required
            or cycle["id"] in ids
            or not re.fullmatch(r"CYCLE-[A-Z0-9-]{1,48}", cycle["id"])
        ):
            raise CaseStudyError("malformed_or_replayed_cycle")
        if (
            cycle["task_revision"] != expected_revision
            or cycle["autonomy"]
            not in {"autonomous", "human_assisted", "blocked", "externally_resolved"}
            or not isinstance(cycle["roles"], list)
            or not cycle["roles"]
            or not isinstance(cycle["concurrency"], int)
            or cycle["concurrency"] < 1
            or not isinstance(cycle["interventions"], int)
            or cycle["interventions"] < 0
            or not isinstance(cycle["blocked"], bool)
            or not isinstance(cycle["retries"], int)
            or cycle["retries"] < 0
            or cycle["terminal"] not in {"completed", "blocked", "reconciled"}
        ):
            raise CaseStudyError("invalid_cycle_classification")
        _d(cycle["project_digest"], "project_digest")
        _d(cycle["evidence_digest"], "cycle_evidence")
        if cycle["evidence_digest"] != digest(
            {k: cycle[k] for k in cycle if k != "evidence_digest"}
        ):
            raise CaseStudyError("cycle_digest_mismatch")
        ids.add(cycle["id"])
    findings = record["findings"]
    if not isinstance(findings, list) or not findings:
        raise CaseStudyError("missing_findings")
    for finding in findings:
        if (
            set(finding)
            != {"kind", "code", "count", "proposal_only", "evidence_digest"}
            or finding["kind"] not in KINDS
            or not re.fullmatch(r"[a-z][a-z0-9_]{2,48}", finding["code"])
            or not isinstance(finding["count"], int)
            or finding["count"] < 1
            or finding["proposal_only"] is not True
        ):
            raise CaseStudyError("invalid_finding_or_approval")
        _d(finding["evidence_digest"], "finding_evidence")
        if finding["evidence_digest"] != digest(
            {k: finding[k] for k in finding if k != "evidence_digest"}
        ):
            raise CaseStudyError("finding_digest_mismatch")
    if record["analysis"] != {
        "cross_project": True,
        "approval": "not_performed",
        "policy_mutation": "not_performed",
        "guidance_authoring": "not_performed",
        "projects": len({c["project_digest"] for c in cycles}),
    }:
        raise CaseStudyError("analysis_boundary_violation")
    evidence = record["evidence"]
    if (
        set(evidence) != {"record_digest", "checker"}
        or evidence["checker"] != "awr-case-study-loop-checker/1.0.0"
        or evidence["record_digest"]
        != digest({k: record[k] for k in record if k != "evidence"})
    ):
        raise CaseStudyError("record_digest_mismatch")
    if not _safe(record):
        raise CaseStudyError("privacy_violation")
    return {
        "checker": evidence["checker"],
        "task_revision": 3,
        "cycles": len(cycles),
        "findings": len(findings),
        "projects": record["analysis"]["projects"],
        "proposal_only": True,
        "policy_mutation": "not_performed",
    }

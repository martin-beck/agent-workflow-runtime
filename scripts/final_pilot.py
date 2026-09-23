#!/usr/bin/env python3
"""Deterministic offline AR-0060 final-pilot composition checker."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-final-pilot-operational-acceptance", "version": "1.0.0"}
TASK = {"id": "AR-0060", "revision": 5}
GATES = (
    "coordinator_admission", "capability_preflight", "security_hardening",
    "production_readiness", "performance_reliability", "chaos_qualification",
    "deployment_release", "publication_review", "operational_acceptance",
)
DEPENDS = {gate: list(GATES[:index]) for index, gate in enumerate(GATES)}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|executable|network", re.I)
SAFE_POLICY_KEYS = {"network", "provider", "llm", "live_service", "durable_state", "publication", "remote_verification", "operational_acceptance", "execute", "status"}


class FinalPilotError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return all((str(key) in SAFE_POLICY_KEYS or not PRIVATE.search(str(key))) and _safe(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_safe(item) for item in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise FinalPilotError("invalid " + name)


def validate(record, expected_revision=5, expected_worktree="agent-workflow-runtime-0060"):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "gates", "terminal", "evidence"}
    if not isinstance(record, dict) or set(record) != required or not _safe(record):
        raise FinalPilotError("unknown, missing, or privacy-bearing field")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != TASK or expected_revision != 5:
        raise FinalPilotError("unsupported or stale task binding")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64}:
        raise FinalPilotError("invalid project binding")
    if record["worktree"] != {"key": expected_worktree, "digest": "sha256:" + "2" * 64}:
        raise FinalPilotError("invalid worktree binding")
    if set(record["session"]) != {"id"} or not re.fullmatch(r"SES-AR0060-[A-Z0-9-]{1,48}", record["session"]["id"]):
        raise FinalPilotError("invalid session binding")
    if not isinstance(record["gates"], list) or len(record["gates"]) != len(GATES):
        raise FinalPilotError("incomplete gate composition")
    seen = set()
    for index, gate in enumerate(record["gates"], 1):
        fields = {"id", "sequence", "depends_on", "status", "task_revision", "worktree_digest", "evidence_digest"}
        if not isinstance(gate, dict) or set(gate) != fields or gate["id"] != GATES[index - 1] or gate["sequence"] != index:
            raise FinalPilotError("missing, reordered, or unknown gate")
        if gate["id"] in seen or gate["depends_on"] != DEPENDS[gate["id"]]:
            raise FinalPilotError("duplicate or incomplete gate dependency")
        if gate["status"] != "qualified" or gate["task_revision"] != 5 or gate["worktree_digest"] != record["worktree"]["digest"]:
            raise FinalPilotError("gate is not qualified or binding is stale")
        _digest(gate["evidence_digest"], "gate evidence digest")
        unsigned = dict(gate); unsigned.pop("evidence_digest")
        if gate["evidence_digest"] != digest(unsigned):
            raise FinalPilotError("tampered gate evidence")
        seen.add(gate["id"])
    terminal = {"status": "qualified_offline", "operational_acceptance": "blocked_pending_live_evidence", "execute": False, "provider": "not_performed", "network": "disabled", "llm": "not_performed", "live_service": "not_performed", "durable_state": "not_performed", "publication": "not_performed", "remote_verification": "unverified"}
    if record["terminal"] != terminal:
        raise FinalPilotError("unsafe terminal projection")
    evidence = record["evidence"]
    if set(evidence) != {"checker", "task_revision", "specification_digest", "record_digest"} or evidence["checker"] != "awr-final-pilot-operational-acceptance-checker/1.0.0" or evidence["task_revision"] != 5:
        raise FinalPilotError("invalid evidence envelope")
    _digest(evidence["specification_digest"], "specification digest")
    _digest(evidence["record_digest"], "record digest")
    if evidence["record_digest"] != digest({key: value for key, value in record.items() if key != "evidence"}):
        raise FinalPilotError("record digest mismatch")
    return {"contract": "awr-final-pilot-operational-acceptance@1.0.0", "task_revision": 5, "status": "qualified_offline", "gates": len(GATES), "operational_acceptance": "blocked_pending_live_evidence", "execute": False, "provider": "not_performed", "network": "disabled", "remote_verification": "unverified"}

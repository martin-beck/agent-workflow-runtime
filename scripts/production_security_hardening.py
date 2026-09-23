#!/usr/bin/env python3
"""Deterministic offline AR-0057 production security hardening model."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-production-security-hardening", "version": "1.0.0"}
TASK = {"id": "AR-0057", "revision": 5}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
PRIVATE = re.compile(r"credential|password|secret_value|token_value|prompt|transcript|private.?path|host.?identifier|raw.?output|network.?address|command|executable", re.I)
PRIVATE_VALUE = re.compile(r"BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|(?:password|token|secret|credential)\s*[:=]", re.I)
CONTROLS = ("dependency_verification", "key_rotation", "secret_references", "least_privilege", "sandbox_egress", "privacy_scan", "audit_integrity", "vulnerability_response", "degraded_verification")


class SecurityError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise SecurityError("malformed " + name)
    return value


def _d(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise SecurityError("invalid " + name)


def _safe(value):
    if isinstance(value, dict):
        allowed = {"secrets", "private_values", "secret_references", "values_absent", "references_only", "raw_payloads"}
        return all((str(k) in allowed or not PRIVATE.search(str(k))) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (PRIVATE_VALUE.search(value) or len(value) > 256))


def _control(record, name):
    control = _obj(record[name], {"status", "evidence_digest"}, name)
    if control["status"] != "pass":
        raise SecurityError(name + " did not pass")
    _d(control["evidence_digest"], name + " evidence digest")
    return control


def validate(record, expected_revision=5):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "session", *CONTROLS, "audit", "evidence"}
    _obj(record, fields, "security record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != TASK or expected_revision != 5:
        raise SecurityError("unsupported or stale task binding")
    project = _obj(record["project"], {"key", "revision"}, "project")
    if project["key"] != "agent-workflow-runtime":
        raise SecurityError("invalid project binding")
    _d(project["revision"], "project revision")
    worktree = _obj(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != "agent-workflow-runtime-0057":
        raise SecurityError("invalid worktree binding")
    _d(worktree["digest"], "worktree digest")
    if not isinstance(record["session"], str) or not ID.fullmatch(record["session"]):
        raise SecurityError("invalid session binding")

    dependency = _control(record, "dependency_verification")
    if dependency != {"status": "pass", "evidence_digest": dependency["evidence_digest"]}:
        raise SecurityError("dependency control shape")
    details = record["dependency_verification"]
    # The detailed observations are nested under evidence to keep the public control projection bounded.
    evidence = _obj(record["evidence"], {"dependencies", "keys", "secrets", "privilege", "sandbox", "privacy", "audit_digest", "vulnerabilities", "degradation", "record_digest"}, "evidence")
    dependencies = evidence["dependencies"]
    if not isinstance(dependencies, list) or not 1 <= len(dependencies) <= 32:
        raise SecurityError("invalid dependency observations")
    names = set()
    for item in dependencies:
        item = _obj(item, {"name", "version", "source", "integrity_digest", "signature", "dco", "sbom_digest", "license_digest"}, "dependency")
        if not isinstance(item["name"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item["name"]) or item["name"] in names or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", item["version"]):
            raise SecurityError("dependency is floating or duplicated")
        if item["source"] not in {"registry_pinned", "vendored", "git_pinned"} or item["signature"] != "valid" or item["dco"] != "signed":
            raise SecurityError("dependency signature or DCO failure")
        for key in ("integrity_digest", "sbom_digest", "license_digest"):
            _d(item[key], key)
        names.add(item["name"])
    keys = evidence["keys"]
    if _obj(keys, {"active_key_digest", "next_key_digest", "rotation_due", "old_keys_revoked", "review_required"}, "key rotation")["rotation_due"] is not False or keys["old_keys_revoked"] is not True or keys["review_required"] is not True or keys["active_key_digest"] == keys["next_key_digest"]:
        raise SecurityError("stale or unsafe key rotation")
    _d(keys["active_key_digest"], "active key"); _d(keys["next_key_digest"], "next key")
    secrets = _obj(evidence["secrets"], {"references_only", "values_absent", "manager", "versioned", "cleanup"}, "secret references")
    if secrets != {**secrets, "references_only": True, "values_absent": True, "versioned": True, "cleanup": "on_completion_or_cancel"} or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", secrets["manager"]):
        raise SecurityError("secret value or unsafe reference")
    privilege = _obj(evidence["privilege"], {"granted", "denied", "elevation"}, "least privilege")
    if set(privilege["granted"]) != {"read", "edit", "test"} or set(privilege["denied"]) != {"network", "credentials", "provider", "llm", "durable_state"} or privilege["elevation"] != "none":
        raise SecurityError("least privilege violation")
    sandbox = _obj(evidence["sandbox"], {"argv_only", "inherit_environment", "filesystem", "egress", "process_tree", "escape_attempts"}, "sandbox")
    if sandbox != {**sandbox, "argv_only": True, "inherit_environment": False, "filesystem": "worktree_only", "egress": "deny_by_default", "process_tree": "bounded_and_cleaned", "escape_attempts": "rejected"}:
        raise SecurityError("sandbox or egress bypass")
    privacy = _obj(evidence["privacy"], {"scan_status", "raw_payloads", "private_values", "public_projection"}, "privacy scan")
    if privacy != {**privacy, "scan_status": "pass", "raw_payloads": "absent", "private_values": "absent", "public_projection": "digest_only"}:
        raise SecurityError("privacy scan failed")
    audit = record["audit"]
    if not isinstance(audit, list) or len(audit) < 2 or len(audit) > 32:
        raise SecurityError("invalid audit chain")
    previous = digest("genesis")
    for item in audit:
        item = _obj(item, {"sequence", "event_id", "action", "previous_digest", "event_digest"}, "audit event")
        if item["previous_digest"] != previous or item["sequence"] != audit.index(item) + 1 or not ID.fullmatch(item["event_id"]) or not isinstance(item["action"], str) or len(item["action"]) > 64 or item["event_digest"] != digest({k: item[k] for k in item if k != "event_digest"}):
            raise SecurityError("audit manipulation")
        previous = item["event_digest"]
    if evidence["audit_digest"] != previous:
        raise SecurityError("audit digest mismatch")
    vulnerabilities = _obj(evidence["vulnerabilities"], {"severity_bound", "triage_sla_hours", "stop_on_critical", "incident_reference_only"}, "vulnerability response")
    if vulnerabilities != {**vulnerabilities, "severity_bound": "critical_high_medium_low", "triage_sla_hours": 24, "stop_on_critical": True, "incident_reference_only": True}:
        raise SecurityError("vulnerability response is unsafe")
    degradation = _obj(evidence["degradation"], {"missing_signature", "missing_sbom", "stale_key", "scanner_unavailable", "audit_failure"}, "degraded verification")
    if any(value != "fail_closed" for value in degradation.values()):
        raise SecurityError("degraded verification did not fail closed")
    for name in CONTROLS:
        _control(record, name)
    if not _safe(record):
        raise SecurityError("privacy-bearing security record")
    body = {key: record[key] for key in record if key != "evidence"}
    body["audit"] = record["audit"]
    if record["evidence"]["record_digest"] != digest({"record": body, "evidence": {key: value for key, value in evidence.items() if key != "record_digest"}}):
        raise SecurityError("record digest mismatch")
    return {"contract": "awr-production-security-hardening@1.0.0", "task_revision": 5, "status": "pass", "controls": len(CONTROLS), "dependencies": len(dependencies), "audit_events": len(audit), "live_review": "required", "provider": "not_performed", "network": "disabled", "durable_state": "not_performed"}

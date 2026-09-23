#!/usr/bin/env python3
"""Deterministic, offline AR-0058 packaging and release model."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-production-deployment-release", "version": "1.0.0"}
TASK = {"id": "AR-0058", "revision": 5}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|executable|network", re.I)
SAFE_POLICY_KEYS = {"network", "credentials"}
HEX_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class DeploymentReleaseError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise DeploymentReleaseError("malformed " + name)
    return value


def _d(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise DeploymentReleaseError("invalid " + name)


def _safe(value):
    if isinstance(value, dict):
        return all((str(k) in SAFE_POLICY_KEYS or not PRIVATE.search(str(k))) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def _version(value, name):
    if not isinstance(value, str) or not HEX_VERSION.fullmatch(value):
        raise DeploymentReleaseError("invalid " + name)


def _phase(value, name):
    if not isinstance(value, dict) or not {"status", "evidence_digest"}.issubset(value):
        raise DeploymentReleaseError("malformed " + name)
    phase = value
    if phase["status"] != "qualified":
        raise DeploymentReleaseError(name + " is not qualified")
    _d(phase["evidence_digest"], name + " evidence digest")


def validate(record, expected_revision=5, expected_worktree="agent-workflow-runtime-0058"):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "session", "packaging", "deployment", "compatibility", "upgrade", "rollback", "release", "evidence"}
    _obj(record, fields, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != TASK or expected_revision != 5:
        raise DeploymentReleaseError("unsupported or stale task binding")
    project = _obj(record["project"], {"key", "revision"}, "project")
    if project["key"] != "agent-workflow-runtime":
        raise DeploymentReleaseError("invalid project binding")
    _d(project["revision"], "project revision")
    worktree = _obj(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree:
        raise DeploymentReleaseError("invalid worktree binding")
    _d(worktree["digest"], "worktree digest")
    if not isinstance(record["session"], str) or not re.fullmatch(r"SES-AR0058-[A-Z0-9-]{1,48}", record["session"]):
        raise DeploymentReleaseError("invalid session binding")

    for name in ("packaging", "deployment", "compatibility", "upgrade", "rollback", "release"):
        _phase(record[name], name)

    packaging = _obj(record["packaging"], {"status", "evidence_digest", "artifact", "sbom", "signature", "dco"}, "packaging")
    _obj(packaging["artifact"], {"name", "version", "source_digest", "artifact_digest", "format"}, "artifact")
    if not IDENTIFIER.fullmatch(packaging["artifact"]["name"]) or packaging["artifact"]["format"] not in {"tar", "wheel", "container"}:
        raise DeploymentReleaseError("invalid artifact")
    _version(packaging["artifact"]["version"], "artifact version")
    _d(packaging["artifact"]["source_digest"], "source digest")
    _d(packaging["artifact"]["artifact_digest"], "artifact digest")
    if packaging["artifact"]["source_digest"] == packaging["artifact"]["artifact_digest"]:
        raise DeploymentReleaseError("source and artifact digests must differ")
    if packaging["sbom"] != "supplied_digest" or packaging["signature"] != "supplied_observation" or packaging["dco"] != "supplied_observation":
        raise DeploymentReleaseError("incomplete package provenance")

    deployment = _obj(record["deployment"], {"status", "evidence_digest", "strategy", "target", "execute", "network", "credentials", "health_gate"}, "deployment")
    if deployment["strategy"] not in {"blue_green", "canary", "rolling"} or deployment["target"] != "supplied_target" or deployment["execute"] is not False or deployment["network"] != "disabled" or deployment["credentials"] != "not_required" or deployment["health_gate"] != "supplied_observation":
        raise DeploymentReleaseError("deployment exceeds offline boundary")

    compatibility = _obj(record["compatibility"], {"status", "evidence_digest", "runtime", "platform", "contracts"}, "compatibility")
    for key in ("runtime", "platform"):
        item = _obj(compatibility[key], {"name", "version", "digest"}, key)
        if not IDENTIFIER.fullmatch(item["name"]):
            raise DeploymentReleaseError("invalid " + key + " name")
        _version(item["version"], key + " version")
        _d(item["digest"], key + " digest")
    if not isinstance(compatibility["contracts"], list) or not 1 <= len(compatibility["contracts"]) <= 16:
        raise DeploymentReleaseError("invalid compatibility contracts")
    seen = set()
    for item in compatibility["contracts"]:
        item = _obj(item, {"id", "version", "digest", "mode"}, "compatibility contract")
        if not IDENTIFIER.fullmatch(item["id"]) or item["id"] in seen or item["mode"] != "exact":
            raise DeploymentReleaseError("replayed or non-exact compatibility contract")
        _version(item["version"], "contract version"); _d(item["digest"], "contract digest"); seen.add(item["id"])

    upgrade = _obj(record["upgrade"], {"status", "evidence_digest", "from_version", "to_version", "migration", "interruption_recovery", "downgrade_guard"}, "upgrade")
    _version(upgrade["from_version"], "upgrade source version"); _version(upgrade["to_version"], "upgrade target version")
    if upgrade["from_version"] == upgrade["to_version"] or upgrade["migration"] != "bounded_reversible" or upgrade["interruption_recovery"] != "checkpoint_required" or upgrade["downgrade_guard"] != "exact_target_only":
        raise DeploymentReleaseError("unsafe upgrade plan")

    rollback = _obj(record["rollback"], {"status", "evidence_digest", "target_version", "target_digest", "execution", "durable_state", "recovery_gate"}, "rollback")
    if rollback["target_version"] != upgrade["from_version"] or rollback["target_digest"] != packaging["artifact"]["source_digest"] or rollback["execution"] != "not_performed" or rollback["durable_state"] != "not_performed" or rollback["recovery_gate"] != "supplied_observation":
        raise DeploymentReleaseError("rollback is not exact-target and non-executing")

    release = _obj(record["release"], {"status", "evidence_digest", "automation", "publication", "remote_verification", "execute", "steps"}, "release")
    if release["automation"] != "bounded_plan" or release["publication"] != "not_performed" or release["remote_verification"] != "unverified" or release["execute"] is not False:
        raise DeploymentReleaseError("release exceeds offline boundary")
    if release["steps"] != ["package", "verify", "compatibility_check", "upgrade_prepare", "rollback_prepare", "release_gate"]:
        raise DeploymentReleaseError("unbounded or reordered release plan")
    if not _safe(record):
        raise DeploymentReleaseError("privacy-bearing record")
    evidence = _obj(record["evidence"], {"specification_digest", "record_digest", "checker"}, "evidence")
    _d(evidence["specification_digest"], "specification digest"); _d(evidence["record_digest"], "record digest")
    body = {key: record[key] for key in record if key != "evidence"}
    if evidence["record_digest"] != digest(body) or evidence["checker"] != "awr-production-deployment-release-checker/1.0.0":
        raise DeploymentReleaseError("evidence digest mismatch")
    return {"contract": "awr-production-deployment-release@1.0.0", "task_revision": 5, "status": "qualified", "packaging": "qualified", "deployment": "prepared", "compatibility": "compatible", "upgrade": "prepared", "rollback": "ready", "release": "not_performed", "publication": "not_performed", "remote_verification": "unverified", "network": "disabled", "durable_state": "not_performed", "execute": False}

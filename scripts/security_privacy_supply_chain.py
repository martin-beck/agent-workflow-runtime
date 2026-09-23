#!/usr/bin/env python3
"""Offline AR-0025 security, privacy, and supply-chain assurance model."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-security-privacy-supply-chain", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|PRJ-[A-Z0-9-]{1,63}|SES-[A-Z0-9-]{1,63}|EV-[A-Z0-9-]{1,63})$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
PRIVATE_KEY = re.compile(r"(?:password|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential|secret)\s*[:=]", re.I)
CAPABILITIES = {"read", "edit", "test"}
DENIED = {"network", "credentials", "provider", "llm", "durable_state"}
COMPONENTS = ("secret_handling", "least_privilege", "dependency_provenance", "redaction", "public_evidence", "hostile_boundaries")


class AssuranceError(ValueError):
    """A fail-closed AR-0025 violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise AssuranceError("malformed " + name)
    return value


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise AssuranceError("invalid " + name)


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEY.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(location)
    return errors


def validate(record, expected_revision=1, *, expected_task="AR-0025", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0025"):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "session", *COMPONENTS, "evidence"}
    _object(record, fields, "assurance record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise AssuranceError("unsupported assurance protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision}:
        raise AssuranceError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise AssuranceError("invalid project binding")
    _digest(project["revision"], "project revision")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree or not WORKTREE.fullmatch(worktree["key"]):
        raise AssuranceError("invalid worktree binding")
    _digest(worktree["digest"], "worktree digest")
    if not isinstance(record["session"], str) or not ID.fullmatch(record["session"]):
        raise AssuranceError("invalid session binding")

    secret = _object(record["secret_handling"], {"status", "secrets_exposed", "storage", "transport", "evidence_digest"}, "secret handling")
    if secret["status"] != "pass" or secret["secrets_exposed"] is not False or secret["storage"] != "none" or secret["transport"] != "none":
        raise AssuranceError("secret handling is unsafe")
    privilege = _object(record["least_privilege"], {"status", "granted", "denied", "elevation", "evidence_digest"}, "least privilege")
    if privilege["status"] != "pass" or set(privilege["granted"]) != CAPABILITIES or set(privilege["denied"]) != DENIED or privilege["elevation"] != "none":
        raise AssuranceError("least privilege boundary is invalid")
    if not isinstance(privilege["granted"], list) or not isinstance(privilege["denied"], list) or len(privilege["granted"]) != 3 or len(privilege["denied"]) != 5:
        raise AssuranceError("capability lists are malformed")
    provenance = _object(record["dependency_provenance"], {"status", "manifest_digest", "lockfile_digest", "dependencies", "evidence_digest"}, "dependency provenance")
    if provenance["status"] != "pass":
        raise AssuranceError("dependency provenance is not passing")
    _digest(provenance["manifest_digest"], "manifest digest"); _digest(provenance["lockfile_digest"], "lockfile digest")
    if not isinstance(provenance["dependencies"], list) or not 1 <= len(provenance["dependencies"]) <= 32:
        raise AssuranceError("invalid dependency list")
    names = set()
    for dependency in provenance["dependencies"]:
        dependency = _object(dependency, {"name", "version", "source", "integrity_digest", "license_digest"}, "dependency")
        if not isinstance(dependency["name"], str) or not PACKAGE.fullmatch(dependency["name"]) or dependency["name"] in names or not VERSION.fullmatch(str(dependency["version"])) or dependency["source"] not in {"registry", "vendored", "git_pinned"}:
            raise AssuranceError("dependency is floating or duplicated")
        _digest(dependency["integrity_digest"], "dependency integrity digest"); _digest(dependency["license_digest"], "dependency license digest")
        names.add(dependency["name"])
    redaction = _object(record["redaction"], {"status", "raw_content_absent", "digest_only", "private_values_absent", "evidence_digest"}, "redaction")
    if redaction != {**redaction, "status": "pass", "raw_content_absent": True, "digest_only": True, "private_values_absent": True}:
        raise AssuranceError("redaction is incomplete")
    public = _object(record["public_evidence"], {"status", "allowed_fields", "payload_free", "publication", "evidence_digest"}, "public evidence")
    if public["status"] != "pass" or public["allowed_fields"] != ["identifiers", "enums", "booleans", "versions", "digests"] or public["payload_free"] is not True or public["publication"] != "not_performed":
        raise AssuranceError("public evidence is unsafe")
    hostile = _object(record["hostile_boundaries"], {"status", "unknown_rejected", "stale_rejected", "replay_rejected", "cross_binding_rejected", "credential_rejected", "evidence_digest"}, "hostile boundaries")
    if hostile != {**hostile, "status": "pass", "unknown_rejected": True, "stale_rejected": True, "replay_rejected": True, "cross_binding_rejected": True, "credential_rejected": True}:
        raise AssuranceError("hostile boundaries are incomplete")
    for component in COMPONENTS:
        _digest(record[component]["evidence_digest"], component + " evidence digest")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or len(evidence) != 7:
        raise AssuranceError("invalid evidence count")
    expected_kinds = set(COMPONENTS) | {"binding"}; seen = set(); digests = set(); ids = set()
    components = {key: record[key] for key in COMPONENTS}
    components["binding"] = {"task": task, "project": project, "worktree": worktree, "session": record["session"]}
    for item in evidence:
        item = _object(item, {"id", "kind", "digest"}, "evidence item")
        if not isinstance(item["id"], str) or not ID.fullmatch(item["id"]) or item["id"] in ids or item["kind"] not in expected_kinds or item["kind"] in seen:
            raise AssuranceError("replayed or invalid evidence")
        _digest(item["digest"], "evidence digest")
        if item["digest"] in digests or item["digest"] != sha256(canonical_bytes(components[item["kind"]])):
            raise AssuranceError("mismatched evidence digest")
        ids.add(item["id"]); seen.add(item["kind"]); digests.add(item["digest"])
    if seen != expected_kinds or _safe(record):
        raise AssuranceError("privacy-bearing or incomplete assurance record")
    return {"task_revision": expected_revision, "session": record["session"], "dependencies": len(provenance["dependencies"]), "status": "pass", "publication": "not_performed"}

#!/usr/bin/env python3
"""Deterministic offline security, privacy, and supply-chain policy gate."""

import hashlib
import json
import re


PROTOCOL = {"id": "awr-security-policy-gate", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|PRJ-[A-Z0-9-]{1,63}|SES-[A-Z0-9-]{1,63}|EV-[A-Z0-9-]{1,63})$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
PRIVATE_KEY = re.compile(r"(?:password|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data|secret)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential|secret)\s*[:=]", re.I)
COMPONENTS = ("policy_gate", "provenance", "sbom", "signature", "privacy", "security_evidence")


class SecurityPolicyError(ValueError):
    """A fail-closed policy violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise SecurityPolicyError("malformed " + name)
    return value


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise SecurityPolicyError("invalid " + name)


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEY.search(str(key)) and not ((str(key) == "credential_refs" and child is False) or (str(key) in {"secret_values_absent", "private_paths_absent"} and child is True)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(location)
    return errors


def validate(record, expected_revision=3, *, expected_task="AR-0042", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0042"):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "session", *COMPONENTS, "evidence", "execution"}
    _object(record, fields, "security policy record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise SecurityPolicyError("unsupported policy protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or expected_revision != 3:
        raise SecurityPolicyError("AR-0042 requires Coordinator revision 3")
    project = _object(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise SecurityPolicyError("invalid project binding")
    _digest(project["revision"], "project revision")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree or not WORKTREE.fullmatch(worktree["key"]):
        raise SecurityPolicyError("invalid worktree binding")
    _digest(worktree["digest"], "worktree digest")
    if not isinstance(record["session"], str) or not ID.fullmatch(record["session"]):
        raise SecurityPolicyError("invalid session binding")

    policy = _object(record["policy_gate"], {"status", "mode", "granted", "denied", "approval", "credential_refs", "command_form", "evidence_digest"}, "policy gate")
    if policy["status"] != "pass" or policy["mode"] != "offline" or policy["granted"] != ["read", "edit", "test"] or policy["denied"] != ["network", "credentials", "provider", "llm", "durable_state", "publication"] or policy["approval"] != "not_required_offline" or policy["credential_refs"] is not False or policy["command_form"] != "bounded_argv":
        raise SecurityPolicyError("offline policy gate is unsafe")

    provenance = _object(record["provenance"], {"status", "manifest_digest", "lockfile_digest", "generated_from_lock", "dependencies", "evidence_digest"}, "provenance")
    if provenance["status"] != "pass" or provenance["generated_from_lock"] is not True:
        raise SecurityPolicyError("dependency provenance is not passing")
    _digest(provenance["manifest_digest"], "manifest digest"); _digest(provenance["lockfile_digest"], "lockfile digest")
    if not isinstance(provenance["dependencies"], list) or not 1 <= len(provenance["dependencies"]) <= 32:
        raise SecurityPolicyError("invalid dependency list")
    names = set()
    for dependency in provenance["dependencies"]:
        dependency = _object(dependency, {"name", "version", "source", "integrity_digest", "license_digest"}, "dependency")
        if not isinstance(dependency["name"], str) or not PACKAGE.fullmatch(dependency["name"]) or dependency["name"] in names or not VERSION.fullmatch(str(dependency["version"])) or dependency["source"] not in {"registry", "vendored", "git_pinned"}:
            raise SecurityPolicyError("dependency is floating or duplicated")
        _digest(dependency["integrity_digest"], "dependency integrity digest"); _digest(dependency["license_digest"], "dependency license digest")
        names.add(dependency["name"])

    sbom = _object(record["sbom"], {"status", "format", "digest", "dependency_count", "complete", "evidence_digest"}, "SBOM")
    if sbom["status"] != "pass" or sbom["format"] != "spdx-json" or sbom["complete"] is not True or sbom["dependency_count"] != len(provenance["dependencies"]):
        raise SecurityPolicyError("SBOM is incomplete")
    _digest(sbom["digest"], "SBOM digest")

    signature = _object(record["signature"], {"status", "algorithm", "artifact_digest", "key_digest", "dco", "verification", "evidence_digest"}, "signature")
    if signature["status"] != "valid" or signature["algorithm"] != "ssh-ed25519" or signature["dco"] != "signed" or signature["verification"] != "supplied_observation":
        raise SecurityPolicyError("signature or DCO evidence is not fail-closed")
    _digest(signature["artifact_digest"], "artifact digest"); _digest(signature["key_digest"], "signing key digest")

    privacy = _object(record["privacy"], {"status", "raw_content_absent", "secret_values_absent", "private_paths_absent", "allowed_fields", "evidence_digest"}, "privacy")
    if privacy["status"] != "pass" or privacy["raw_content_absent"] is not True or privacy["secret_values_absent"] is not True or privacy["private_paths_absent"] is not True or privacy["allowed_fields"] != ["identifiers", "enums", "booleans", "versions", "digests"]:
        raise SecurityPolicyError("privacy projection is unsafe")
    security = _object(record["security_evidence"], {"status", "disposition", "publication", "remote_verification", "evidence_digest"}, "security evidence")
    if security != {**security, "status": "pass", "disposition": "offline_qualified_live_unverified", "publication": "not_performed", "remote_verification": "unverified"}:
        raise SecurityPolicyError("security evidence is not fail-closed")
    for component in COMPONENTS:
        _digest(record[component]["evidence_digest"], component + " evidence digest")
    execution = _object(record["execution"], {"mode", "network", "provider", "llm", "coordinator", "durable_state", "live_verification"}, "execution")
    if execution != {"mode": "offline_fixture", "network": "disabled", "provider": "not_performed", "llm": "not_performed", "coordinator": "not_performed", "durable_state": "not_performed", "live_verification": "unverified"}:
        raise SecurityPolicyError("external execution claim")

    evidence = record["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(COMPONENTS) + 1:
        raise SecurityPolicyError("invalid evidence count")
    expected_kinds = set(COMPONENTS) | {"binding"}; seen = set(); ids = set(); digests = set()
    components = {key: record[key] for key in COMPONENTS}
    components["binding"] = {"task": task, "project": project, "worktree": worktree, "session": record["session"]}
    for item in evidence:
        item = _object(item, {"id", "kind", "digest"}, "evidence item")
        if not isinstance(item["id"], str) or not ID.fullmatch(item["id"]) or item["id"] in ids or item["kind"] not in expected_kinds or item["kind"] in seen:
            raise SecurityPolicyError("replayed or invalid evidence")
        _digest(item["digest"], "evidence digest")
        if item["digest"] in digests or item["digest"] != sha256(canonical_bytes(components[item["kind"]])):
            raise SecurityPolicyError("mismatched evidence digest")
        ids.add(item["id"]); seen.add(item["kind"]); digests.add(item["digest"])
    if seen != expected_kinds or _safe(record):
        raise SecurityPolicyError("privacy-bearing or incomplete security record")
    return {"task_revision": 3, "session": record["session"], "dependencies": len(provenance["dependencies"]), "status": "pass", "live_verification": "unverified"}

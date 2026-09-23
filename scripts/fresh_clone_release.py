#!/usr/bin/env python3
"""Offline reference model for the AR-0027 release compatibility lock."""

import re

PROTOCOL = {"id": "awr-fresh-clone-release-lock", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReleaseLockError(ValueError):
    pass


def digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ReleaseLockError("invalid digest")


def bounded_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value):
        raise ReleaseLockError("invalid version")


def validate_dependency(item):
    if not isinstance(item, dict) or set(item) != {"name", "version", "source", "integrity_digest", "license_digest"}:
        raise ReleaseLockError("malformed dependency")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", item["name"]):
        raise ReleaseLockError("invalid dependency name")
    bounded_version(item["version"])
    if item["source"] not in {"stdlib", "repository_lock"}:
        raise ReleaseLockError("unbounded dependency source")
    digest(item["integrity_digest"]); digest(item["license_digest"])


def evaluate_lock(record):
    """Evaluate the state-bearing sections after the envelope is checked."""
    installation = record["installation"]
    if installation["status"] != "reproducible" or installation["network"] != "not_required" or installation["credentials"] != "not_required":
        raise ReleaseLockError("installation is not reproducible offline")
    if len(installation["dependencies"]) != installation["max_dependencies"]:
        raise ReleaseLockError("dependency count mismatch")
    for dependency in installation["dependencies"]:
        validate_dependency(dependency)
    compatibility = record["compatibility"]
    if compatibility["status"] != "compatible" or compatibility["mode"] not in {"exact", "minimum"}:
        raise ReleaseLockError("compatibility is not qualified")
    seen = set()
    for contract in compatibility["contracts"]:
        if not isinstance(contract, dict) or set(contract) != {"id", "version", "mode", "digest"}:
            raise ReleaseLockError("malformed compatibility declaration")
        if contract["id"] in seen or not re.fullmatch(r"awr-[a-z0-9-]+", contract["id"]):
            raise ReleaseLockError("replayed or invalid contract")
        bounded_version(contract["version"]); digest(contract["digest"])
        if contract["mode"] != compatibility["mode"]:
            raise ReleaseLockError("mixed compatibility mode")
        seen.add(contract["id"])
    required_ids = {item.split("@", 1)[0] for item in compatibility["required_contracts"]}
    if seen != required_ids:
        raise ReleaseLockError("required compatibility contract missing")
    release = record["release"]
    if release["status"] != "qualified" or release["publication"] != "not_performed" or release["remote_verification"] != "unverified":
        raise ReleaseLockError("release claim exceeds supplied evidence")
    if release["signature"] != "supplied_observation" or release["dco"] != "supplied_observation":
        raise ReleaseLockError("release evidence is not explicit")
    digest(release["source_head_digest"])
    rollback = record["rollback"]
    if rollback["status"] != "ready" or rollback["execution"] != "not_performed" or rollback["durable_state"] != "not_performed" or rollback["target_digest"] != release["source_head_digest"]:
        raise ReleaseLockError("rollback is not exact-target and non-executing")
    return {"status": "rollback_ready", "installation": "reproducible", "compatibility": "compatible", "publication": "not_performed", "remote_verification": "unverified"}

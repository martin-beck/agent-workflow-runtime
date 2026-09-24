"""Offline artifact provenance and release-recovery verification."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .cli import CliError

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def verify_artifact(artifact: Path, *, version: str, source_commit: str, expected_sha256: str, rollback_version: str | None = None) -> dict[str, Any]:
    artifact = artifact.expanduser().absolute()
    if artifact.is_symlink() or not artifact.is_file():
        raise CliError("release_artifact_invalid")
    if not VERSION.fullmatch(version) or not COMMIT.fullmatch(source_commit) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise CliError("release_provenance_invalid")
    size = artifact.stat().st_size
    if size == 0 or size > 256 * 1024 * 1024:
        raise CliError("release_artifact_size_invalid")
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise CliError("release_digest_mismatch")
    if rollback_version is not None and (not VERSION.fullmatch(rollback_version) or rollback_version == version):
        raise CliError("release_rollback_target_invalid")
    return {"status": "qualified", "version": version, "source_commit": source_commit, "artifact_sha256": actual, "artifact_bytes": size, "rollback_version": rollback_version, "network": "disabled", "publication": "not_performed"}

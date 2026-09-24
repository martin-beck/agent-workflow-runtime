"""Fail-closed local security and isolation checks for the runtime home."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .cli import CliError
from .install import CONFIG, MARKER, STATE, _safe_home, default_home

MANAGED = (CONFIG, STATE, MARKER, "projects.json", "audit.jsonl")
FORBIDDEN = {"credential", "credentials", "password", "secret", "token", "api_key", "apikey"}


def _walk_private(value: Any) -> bool:
    if isinstance(value, dict):
        return any(str(key).lower() in FORBIDDEN or _walk_private(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_walk_private(child) for child in value)
    return False


def check(home: Path | None = None) -> dict[str, Any]:
    selected = _safe_home(home if home is not None else default_home(), create=False)
    mode = stat.S_IMODE(selected.stat().st_mode)
    if mode & 0o077:
        raise CliError("runtime_home_permissions_too_open")
    checked = 0
    for name in MANAGED:
        path = selected / name
        if path.is_symlink():
            raise CliError("managed_file_is_unsafe")
        if not path.exists():
            continue
        if not path.is_file():
            raise CliError("managed_file_is_unsafe")
        file_mode = stat.S_IMODE(path.stat().st_mode)
        if file_mode & 0o077:
            raise CliError("managed_file_permissions_too_open")
        if path.stat().st_size > 4 * 1024 * 1024:
            raise CliError("managed_file_too_large")
        if path.suffix == ".json" or path.name.endswith(".jsonl"):
            try:
                if path.name.endswith(".jsonl"):
                    values = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                else:
                    values = [json.loads(path.read_text(encoding="utf-8"))]
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise CliError("managed_file_invalid") from exc
            if any(_walk_private(value) for value in values):
                raise CliError("credential_material_in_local_state")
        checked += 1
    return {"status": "secure", "managed_files_checked": checked, "network": "disabled", "credentials": "not_stored", "symlinks": "rejected"}

"""Durable local registry for multiple explicitly bound projects."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .cli import CliError, canonical
from .install import _safe_home, default_home

REGISTRY = "projects.json"


def _digest(value: Any) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _load(home: Path) -> dict[str, Any]:
    path = home / REGISTRY
    if not path.exists():
        return {"schema_version": 1, "projects": {}}
    if path.is_symlink() or not path.is_file():
        raise CliError("project_registry_unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CliError("project_registry_corrupt") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("projects"), dict):
        raise CliError("project_registry_incompatible")
    return value


def _save(home: Path, value: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(prefix=".awr-projects-", dir=home)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name, home / REGISTRY)
    except BaseException:
        try: os.unlink(name)
        except OSError: pass
        raise


def register(name: str, project: Path, state: Path, home: Path | None = None) -> dict[str, Any]:
    if not name or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in name) or not name[0].isalpha():
        raise CliError("invalid_project_name")
    project = project.expanduser().absolute(); state = state.expanduser().absolute()
    if project.is_symlink() or state.is_symlink() or not project.is_dir() or not state.is_dir():
        raise CliError("project_or_state_path_invalid")
    binding_file = project / ".awr-project-binding.json"
    state_file = state / "agent-workflow-state.json"
    if not binding_file.is_file() or not state_file.is_file():
        raise CliError("project_state_binding_missing")
    try:
        binding = json.loads(binding_file.read_text(encoding="utf-8"))
        state_record = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CliError("project_state_binding_corrupt") from exc
    if not isinstance(binding, dict) or binding.get("project") != name or state_record.get("project") != name or state_record.get("binding_digest") != _digest(binding):
        raise CliError("project_state_binding_mismatch")
    selected = _safe_home(home if home is not None else default_home(), create=True)
    registry = _load(selected)
    record = {"name": name, "project_path": str(project), "state_path": str(state), "binding_digest": _digest(binding)}
    previous = registry["projects"].get(name)
    if previous is not None and previous != record:
        raise CliError("project_registration_conflict")
    registry["projects"][name] = record
    _save(selected, registry)
    return {"status": "registered" if previous is None else "already_registered", "project": name, "binding_digest": record["binding_digest"], "count": len(registry["projects"]), "network": "disabled"}


def list_projects(home: Path | None = None) -> dict[str, Any]:
    selected = _safe_home(home if home is not None else default_home(), create=True)
    registry = _load(selected)
    return {"status": "ok", "count": len(registry["projects"]), "projects": [{"name": name, "binding_digest": value["binding_digest"]} for name, value in sorted(registry["projects"].items())], "network": "disabled"}

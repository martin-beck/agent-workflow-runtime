"""Safe local bootstrap for a new Agent Workflow-enabled project."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from .cli import CliError, canonical

NAME = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
SCHEMA = 1


def _directory(path: Path, label: str) -> tuple[Path, bool]:
    path = path.expanduser().absolute()
    if path == Path(path.anchor) or path.is_symlink():
        raise CliError(f"unsafe_{label}_path")
    existed = path.exists()
    if existed and not path.is_dir():
        raise CliError(f"{label}_path_not_directory")
    if existed and any(path.iterdir()):
        raise CliError(f"{label}_directory_not_empty")
    return path, existed


def _manifest(name: str, organization: str, state_path: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "kind": "agent-workflow-project",
        "name": name,
        "organization": organization,
        "runtime": {"name": "agent-workflow-runtime", "mode": "local-mock"},
        "authorities": {"coordinator": "external", "quality": "external", "guidance": "external", "ui": "external"},
        "state_path": str(state_path),
        "credentials": "not_provisioned",
        "network": "disabled",
    }


def bootstrap(name: str, organization: str, project: Path, state: Path, *, preview: bool = False) -> dict[str, Any]:
    if not NAME.fullmatch(name) or not NAME.fullmatch(organization):
        raise CliError("invalid_project_identity")
    project, project_existed = _directory(project, "project")
    state, state_existed = _directory(state, "state")
    binding = {"schema_version": SCHEMA, "project": name, "organization": organization, "state_path": str(state), "runtime": "agent-workflow-runtime"}
    if preview:
        return {"status": "preview", "project": str(project), "state": str(state), "binding_digest": _digest(binding), "network": "disabled", "credentials": "not_provisioned"}
    project_manifest = _manifest(name, organization, state)
    product_file = project / "agent-workflow-project.json"
    binding_file = project / ".awr-project-binding.json"
    state_file = state / "agent-workflow-state.json"
    state_readme = state / "README.md"
    created: list[Path] = []
    try:
        if product_file.exists() or binding_file.exists() or state_file.exists() or state_readme.exists():
            raise CliError("bootstrap_layout_already_exists")
        for directory in (project, state):
            if not directory.exists():
                directory.mkdir(parents=True, mode=0o755)
                created.append(directory)
        product_file.write_bytes(canonical(project_manifest) + b"\n")
        binding_file.write_bytes(canonical(binding) + b"\n")
        state_file.write_bytes(canonical({"schema_version": SCHEMA, "kind": "agent-workflow-state", "project": name, "binding_digest": _digest(binding), "tasks": []}) + b"\n")
        state_readme.write_text("# Agent Workflow project state\n\nGenerated state is owned by the Coordinator state workflow.\n", encoding="utf-8")
    except BaseException:
        for path in (product_file, binding_file, state_file, state_readme):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for directory, existed in ((project, project_existed), (state, state_existed)):
            if not existed:
                shutil.rmtree(directory, ignore_errors=True)
        raise
    return {"status": "created", "project": str(project), "state": str(state), "binding_digest": _digest(binding), "network": "disabled", "credentials": "not_provisioned", "authority_mutation": "not_performed"}


def _digest(value: dict[str, Any]) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

"""Adopt an existing Git checkout into the local Agent Workflow control plane."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from .cli import CliError, canonical
from .install import default_home, doctor, install
from .project_registry import register

NAME = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
LOCAL_HELPER = '''#!/usr/bin/env python3
import json, sys
mode, profile, request_digest, ordinal = sys.argv[1:5]
if mode == "interrupt":
    import time
    time.sleep(30)
    raise SystemExit(0)
value = {"id": "setup-local-mock", "object": "chat.completion", "model": "local-deterministic-mock",
         "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "setup-local-mock"}}],
         "usage": {"input_units": 0, "output_units": 0, "total_units": 0}}
print(json.dumps(value, separators=(",", ":")), flush=True)
'''


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _git(root: Path, *args: str, required: bool = True) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=required,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("git_command_failed") from exc
    return result.stdout.strip()


def _git_root(project: Path) -> Path:
    project = project.expanduser().absolute()
    if project.is_symlink() or not project.is_dir():
        raise CliError("existing_project_path_invalid")
    try:
        root = Path(_git(project, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except (CliError, OSError) as exc:
        raise CliError("not_a_git_project") from exc
    if root.is_symlink() or not (root / ".git").exists():
        raise CliError("git_root_invalid")
    return root


def _only_setup_files(status: str) -> bool:
    """Recognize only files owned by this command, without hiding user edits."""
    if not status:
        return True
    allowed = (".awr/", ".awr-project-binding.json")
    for line in status.splitlines():
        path = line[3:].split(" -> ")[-1].strip() if len(line) >= 4 else ""
        if not any(path == item or path.startswith(item) for item in allowed):
            return False
    return True


def _write_managed(path: Path, value: bytes) -> None:
    if path.is_symlink():
        raise CliError("managed_path_is_symlink")
    if path.exists():
        try:
            if path.read_bytes() == value:
                return
        except OSError as exc:
            raise CliError("managed_file_unreadable") from exc
        raise CliError(f"managed_file_conflict:{path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise CliError(f"managed_file_conflict:{path.name}")
    except OSError as exc:
        raise CliError("managed_file_write_failed") from exc


def _starter_graph(name: str, revision: str, worktree_digest: str) -> dict[str, Any]:
    task = {
        "id": "AR-9001",
        "revision": 1,
        "dependencies": [],
        "worktree_key": "existing-project",
        "worktree_digest": worktree_digest,
        "profile_id": "fake-alpha",
        "action_digest": _digest({"action": "project-intake", "project": name, "revision": revision}),
        "max_attempts": 2,
    }
    graph = {
        "schema_version": 1,
        "graph_id": "setup-" + name,
        "project_key": name,
        "project_revision": revision,
        "max_parallelism": 1,
        "tasks": [task],
        "approval": {"authority": "coordinator", "status": "approved", "decision_id": "DEC-SETUP-9001", "graph_digest": ""},
    }
    graph["approval"]["graph_digest"] = _digest({key: value for key, value in graph.items() if key != "approval"})
    return graph


def setup_existing(
    project: Path,
    *,
    name: str | None = None,
    organization: str = "local",
    home: Path | None = None,
    allow_dirty: bool = False,
    start: bool = False,
) -> dict[str, Any]:
    """Create the complete local binding without changing tracked project files."""
    root = _git_root(project)
    project_name = name or re.sub(r"[^a-z0-9-]+", "-", root.name.lower()).strip("-")
    if not NAME.fullmatch(project_name):
        raise CliError("invalid_project_name_use_name_option")
    if not NAME.fullmatch(organization):
        raise CliError("invalid_organization")
    status = _git(root, "status", "--porcelain")
    project_dirty = bool(status) and not _only_setup_files(status)
    if project_dirty and not allow_dirty:
        raise CliError("git_project_dirty_use_allow_dirty")
    head = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "symbolic-ref", "--short", "-q", "HEAD", required=False) or "DETACHED"
    remote = _git(root, "remote", "get-url", "origin", required=False)
    revision = _digest({"head": head, "branch": branch, "dirty": project_dirty})
    worktree_digest = _digest({"project": project_name, "head": head})
    state = root / ".awr" / "state"
    binding = {
        "schema_version": 1, "project": project_name, "organization": organization,
        "state_path": str(state), "runtime": "agent-workflow-runtime",
    }
    manifest = {
        "schema_version": 1, "kind": "agent-workflow-existing-git-project",
        "name": project_name, "organization": organization, "git_root": str(root),
        "git_head": head, "git_branch": branch, "git_dirty": project_dirty,
        "origin_configured": bool(remote), "origin_digest": _digest(remote) if remote else None,
        "state_path": str(state), "runtime": "agent-workflow-runtime",
        "authorities": ["coordinator", "awq", "awg", "ui"],
        "provider": "not_inspected", "credentials": "not_inspected", "network": "disabled",
    }
    graph = _starter_graph(project_name, revision, worktree_digest)
    state_record = {
        "schema_version": 1, "kind": "agent-workflow-existing-git-state", "project": project_name,
        "binding_digest": _digest(binding), "project_revision": revision, "git_head": head,
        "git_branch": branch, "git_dirty": project_dirty, "lifecycle": "ready",
        "provider": "not_performed", "credentials": "not_inspected", "network": "disabled",
    }
    state.mkdir(parents=True, exist_ok=True)
    _write_managed(root / ".awr-project-binding.json", canonical(binding) + b"\n")
    _write_managed(root / ".awr" / "project.json", canonical(manifest) + b"\n")
    _write_managed(state / "agent-workflow-state.json", canonical(state_record) + b"\n")
    _write_managed(root / ".awr" / "workflow-graph.json", canonical(graph) + b"\n")
    helper = root / ".awr" / "agent-session-helper.py"
    _write_managed(helper, LOCAL_HELPER.encode())
    _write_managed(root / ".awr" / "README.md", (
        "# Agent Workflow project control plane\n\n"
        "Generated by `awr setup`. The project remains Git-owned; `.awr` contains "
        "runtime metadata, graph, and durable local state.\n"
    ).encode())
    selected_home = home or default_home()
    health = doctor(selected_home)
    install_result = {"status": "already_healthy"}
    if health["status"] == "not_installed":
        install_result = install(selected_home)
    registered = register(project_name, root, state, selected_home)
    output = {
        "status": "ready", "project": project_name, "project_root": str(root),
        "state": str(state), "graph": str(root / ".awr" / "workflow-graph.json"),
        "project_revision": revision, "git_head": head, "git_branch": branch,
        "git_dirty": project_dirty, "runtime": install_result, "registry": registered,
        "next": f"awr workflow start --graph {root / '.awr' / 'workflow-graph.json'} --state-dir {root / '.awr' / 'run'} --worktree existing-project={root}",
        "provider": "not_inspected", "credentials": "not_inspected", "network": "disabled",
    }
    if start:
        from scripts.autonomous_orchestrator import AutonomousOrchestrator
        runtime_root = Path(__file__).resolve().parents[1]
        runner = AutonomousOrchestrator(
            graph, state_dir=root / ".awr" / "run", worktrees={"existing-project": root},
            registry_spec=runtime_root / "specifications" / "agent-registry-v1.json",
            helper=helper, owner="WRK-SETUP-" + revision[7:19].upper(), max_parallel=1,
        )
        result = runner.run()
        if set(result.get("tasks", {}).values()) != {"completed"}:
            raise CliError("initial_workflow_not_completed")
        output["started"] = result
        output["next"] = "awr workflow status --graph " + str(root / ".awr" / "workflow-graph.json") + " --state-dir " + str(root / ".awr" / "run")
    return output

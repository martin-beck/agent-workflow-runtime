"""Bounded project validation and local mock bootstrap CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


class CliError(ValueError):
    """Invalid input or unsafe local workspace state."""


AUTHORITY_NAMES = {"coordinator", "quality", "guidance", "ui"}
TOP_KEYS = {"schema", "project", "authorities", "runtime_owns"}
PROJECT_KEYS = {"name", "title", "kind", "organization", "state_repository"}
AUTHORITY_KEYS = {"repository", "owns"}
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        raise CliError("empty_yaml_scalar")
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [] if not inner else [_scalar(item) for item in inner.split(",")]
    if text.startswith("\""):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CliError("invalid_yaml_scalar") from exc
        if not isinstance(value, str):
            raise CliError("manifest_scalars_must_be_strings")
        return value
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    if any(token in text for token in ("&", "*", "!", "|", ">", "{", "}")):
        raise CliError("unsupported_yaml_feature")
    if text in {"true", "false", "null", "~"}:
        raise CliError("manifest_scalars_must_be_strings")
    return text


def parse_manifest_yaml(raw: bytes) -> dict[str, Any]:
    """Parse the deliberately small, deterministic YAML subset used by manifests."""
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliError("manifest_not_utf8") from exc
    lines: list[tuple[int, str]] = []
    for number, line in enumerate(source.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:]
        if "\t" in line or indent % 2:
            raise CliError(f"invalid_indentation_line_{number}")
        if len(content) > 1024 or len(lines) >= 400:
            raise CliError("manifest_complexity_limit")
        lines.append((indent, content))
    if not lines:
        raise CliError("empty_manifest")

    def block(index: int, indent: int) -> tuple[Any, int]:
        if lines[index][1].startswith("- "):
            values: list[Any] = []
            while index < len(lines) and lines[index][0] == indent:
                content = lines[index][1]
                if not content.startswith("- "):
                    break
                values.append(_scalar(content[2:]))
                index += 1
                if index < len(lines) and lines[index][0] > indent:
                    raise CliError("nested_yaml_sequence_not_supported")
            return values, index
        result: dict[str, Any] = {}
        while index < len(lines) and lines[index][0] == indent:
            _, content = lines[index]
            if content.startswith("-"):
                raise CliError("invalid_yaml_sequence")
            if ":" not in content:
                raise CliError("invalid_mapping_entry")
            key, value = content.split(":", 1)
            if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in result:
                raise CliError("invalid_or_duplicate_mapping_key")
            index += 1
            if value.strip():
                result[key] = _scalar(value)
            elif index < len(lines) and lines[index][0] > indent:
                if lines[index][0] != indent + 2:
                    raise CliError("invalid_indentation")
                result[key], index = block(index, indent + 2)
            else:
                result[key] = {}
            if index < len(lines) and lines[index][0] < indent:
                break
            if index < len(lines) and lines[index][0] > indent:
                raise CliError("invalid_indentation")
        return result, index

    parsed, end = block(0, lines[0][0])
    if end != len(lines) or not isinstance(parsed, dict):
        raise CliError("invalid_manifest_structure")
    return parsed


def _string(value: Any, pattern: re.Pattern[str], code: str) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_manifest(raw: bytes) -> tuple[dict[str, Any], str]:
    if not isinstance(raw, bytes) or len(raw) > 65536:
        raise CliError("manifest_size_limit")
    manifest = parse_manifest_yaml(raw)
    if set(manifest) != TOP_KEYS or manifest.get("schema") != "1":
        raise CliError("invalid_manifest_top_level")
    project = manifest["project"]
    if not isinstance(project, dict) or set(project) != PROJECT_KEYS:
        raise CliError("invalid_project_section")
    if not all(isinstance(project.get(key), str) and 1 <= len(project[key]) <= 160 for key in PROJECT_KEYS):
        raise CliError("invalid_project_value")
    if not _string(project["name"], IDENTIFIER, "name") or not _string(project["organization"], IDENTIFIER, "organization"):
        raise CliError("invalid_project_identity")
    if not _string(project["state_repository"], REPOSITORY, "state_repository"):
        raise CliError("invalid_state_repository")
    authorities = manifest["authorities"]
    if not isinstance(authorities, dict) or set(authorities) != AUTHORITY_NAMES:
        raise CliError("invalid_authorities")
    for name, authority in authorities.items():
        if not isinstance(authority, dict) or set(authority) != AUTHORITY_KEYS:
            raise CliError("invalid_authority_section")
        if not _string(authority["repository"], REPOSITORY, "repository"):
            raise CliError("invalid_authority_repository")
        owns = authority["owns"]
        if not isinstance(owns, list) or not 1 <= len(owns) <= 32 or any(not isinstance(item, str) or not 1 <= len(item) <= 160 for item in owns):
            raise CliError("invalid_authority_ownership")
    runtime_owns = manifest["runtime_owns"]
    if not isinstance(runtime_owns, list) or not 1 <= len(runtime_owns) <= 32 or any(not isinstance(item, str) or not 1 <= len(item) <= 160 for item in runtime_owns):
        raise CliError("invalid_runtime_ownership")
    return manifest, digest_bytes(raw)


def _read_manifest(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CliError("manifest_unreadable") from exc
    return validate_manifest(raw)


def make_plan(
    manifest: dict[str, Any], revision: str, workspace_label: str, expected_revision: str | None = None
) -> dict[str, Any]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", revision):
        raise CliError("invalid_project_revision")
    if expected_revision is not None and expected_revision != revision:
        raise CliError("stale_project_revision")
    body = {
        "schema_version": 1,
        "project": manifest["project"]["name"],
        "project_revision": revision,
        "workspace": workspace_label,
        "mode": "local_mock",
        "dry_run": True,
        "steps": ["create_project_directory", "write_validated_manifest", "create_local_mock_state"],
        "effects": {
            "provider": "not_performed", "credentials": "not_required", "network": "disabled",
            "coordinator": "not_performed", "awq": "not_performed", "awg": "not_performed", "ui": "not_performed",
        },
    }
    return {**body, "plan_digest": digest_bytes(canonical(body))}


def initialize_mock(manifest: dict[str, Any], revision: str, workspace: Path) -> dict[str, Any]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", revision):
        raise CliError("invalid_project_revision")
    if workspace.is_symlink() or (workspace.exists() and (not workspace.is_dir() or any(workspace.iterdir()))):
        raise CliError("workspace_must_be_absent_or_empty")
    if workspace.resolve() == Path(workspace.anchor) or workspace.name in {"", ".", ".."}:
        raise CliError("unsafe_workspace")
    root = workspace
    project_dir = root / "project"
    state_dir = root / ".awr" / "local-mock"
    if any(path.exists() for path in (project_dir, state_dir)):
        raise CliError("workspace_layout_exists")
    state = {
        "schema_version": 1,
        "kind": "awr-local-mock-state",
        "project": manifest["project"]["name"],
        "project_revision": revision,
        "lifecycle": "new",
        "provider": "not_performed",
        "network": "disabled",
        "credentials": "not_required",
        "authority_state": "not_performed",
    }
    project_manifest = canonical(manifest) + b"\n"
    state_bytes = canonical(state) + b"\n"
    try:
        project_dir.mkdir(parents=True, exist_ok=False)
        state_dir.mkdir(parents=True, exist_ok=False)
        (project_dir / "project-manifest.json").write_bytes(project_manifest)
        (state_dir / "state.json").write_bytes(state_bytes)
    except OSError as exc:
        raise CliError("workspace_creation_failed") from exc
    return {"status": "created", "project_revision": revision, "layout": ["project/project-manifest.json", ".awr/local-mock/state.json"]}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="awr", description="Validate and bootstrap provider-neutral local mock projects.")
    from . import __version__

    root.add_argument("--version", action="version", version=f"awr {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a project manifest")
    validate.add_argument("--manifest", type=Path, required=True)
    init = commands.add_parser("init", help="create a local mock workspace and state layout")
    init.add_argument("--manifest", type=Path, required=True)
    init.add_argument("--workspace", type=Path, required=True)
    plan = commands.add_parser("plan", help="emit a revision-bound dry-run plan")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--workspace", required=True, help="opaque display label; no filesystem access")
    plan.add_argument("--expected-revision", help="require this exact sha256 manifest digest")
    commands.add_parser("version", help="show the installed runtime version")
    for name, help_text in (("install", "initialize a user-owned runtime home"), ("repair", "restore missing runtime files"), ("upgrade", "record the current installed runtime version"), ("rollback", "restore prior runtime installation metadata"), ("uninstall", "remove the runtime marker and preserve user data"), ("doctor", "check runtime-home health")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--home", type=Path, help="runtime home (default: AWR_HOME or the user data directory)")
    project = commands.add_parser("project-init", help="create a new local Agent Workflow project and state binding")
    project.add_argument("--name", required=True)
    project.add_argument("--organization", required=True)
    project.add_argument("--project", type=Path, required=True)
    project.add_argument("--state", type=Path, required=True)
    project.add_argument("--preview", action="store_true")
    board = commands.add_parser("board-acceptance", help="create and autonomously execute a complex provider-free local project")
    board.add_argument("--name", required=True)
    board.add_argument("--organization", required=True)
    board.add_argument("--workspace", type=Path, required=True)
    board.add_argument("--umbrella-root", type=Path, required=True)
    board.add_argument("--runtime-source", type=Path, default=Path(__file__).resolve().parents[1])
    workflow = commands.add_parser("local-run", help="run the deterministic offline mock workflow")
    workflow.add_argument("--manifest", type=Path, required=True)
    workflow.add_argument("--expected-revision")
    register = commands.add_parser("project-register", help="register an existing project/state binding locally")
    register.add_argument("--name", required=True)
    register.add_argument("--project", type=Path, required=True)
    register.add_argument("--state", type=Path, required=True)
    register.add_argument("--home", type=Path)
    commands.add_parser("project-list", help="list locally registered projects").add_argument("--home", type=Path)
    audit = commands.add_parser("audit-record", help="append a privacy-safe digest-only audit event")
    audit.add_argument("--home", type=Path)
    audit.add_argument("--event-id", required=True)
    audit.add_argument("--task-id", required=True)
    audit.add_argument("--task-revision", type=int, required=True)
    audit.add_argument("--category", required=True)
    audit.add_argument("--status", required=True)
    audit.add_argument("--detail", default="")
    commands.add_parser("audit-status", help="validate and summarize the local audit journal").add_argument("--home", type=Path)
    commands.add_parser("security-check", help="check local runtime-home security boundaries").add_argument("--home", type=Path)
    release = commands.add_parser("release-verify", help="verify an offline release artifact and provenance")
    release.add_argument("--artifact", type=Path, required=True)
    release.add_argument("--version", required=True)
    release.add_argument("--source-commit", required=True)
    release.add_argument("--sha256", required=True)
    release.add_argument("--rollback-version")
    coord = commands.add_parser("coord-init", help="initialize a local Coordinator-shaped task state")
    coord.add_argument("--state-file", type=Path, required=True); coord.add_argument("--task-id", required=True); coord.add_argument("--project-revision", required=True); coord.add_argument("--worktree-digest", required=True); coord.add_argument("--session-id", required=True)
    coord_status = commands.add_parser("coord-status", help="read local Coordinator-shaped state")
    coord_status.add_argument("--state-file", type=Path, required=True)
    coord_claim = commands.add_parser("coord-claim", help="claim a local Coordinator-shaped task")
    coord_claim.add_argument("--state-file", type=Path, required=True); coord_claim.add_argument("--owner", required=True); coord_claim.add_argument("--expected-revision", type=int, required=True)
    sched = commands.add_parser("schedule-submit", help="submit a local durable mock job")
    sched.add_argument("--state-file", type=Path, required=True); sched.add_argument("--job-id", required=True); sched.add_argument("--project", required=True); sched.add_argument("--dependency", action="append", default=[]); sched.add_argument("--priority", type=int, default=50)
    dispatch = commands.add_parser("schedule-dispatch", help="dispatch a local ready job")
    dispatch.add_argument("--state-file", type=Path, required=True); dispatch.add_argument("--worker", required=True)
    schedule_done = commands.add_parser("schedule-complete", help="complete a local leased job")
    schedule_done.add_argument("--state-file", type=Path, required=True); schedule_done.add_argument("--job-id", required=True); schedule_done.add_argument("--worker", required=True); schedule_done.add_argument("--lease", required=True); schedule_done.add_argument("--status", default="done")
    commands.add_parser("schedule-status", help="read local scheduler state").add_argument("--state-file", type=Path, required=True)
    agent = commands.add_parser("agent-run", help="run one provider-neutral local agent adapter")
    agent.add_argument("--root", type=Path, required=True); agent.add_argument("--cwd", type=Path, required=True)
    agent.add_argument("--session-id", required=True); agent.add_argument("--adapter", required=True); agent.add_argument("--input-digest", required=True)
    agent.add_argument("--timeout", type=float, default=5.0); agent.add_argument("--sandbox-required", action="store_true"); agent.add_argument("argv", nargs=argparse.REMAINDER)
    gate = commands.add_parser("authority-admit", help="consume mandatory local authority gate observations")
    gate.add_argument("--task", required=True); gate.add_argument("--revision", type=int, required=True)
    qualification = commands.add_parser("qualify-concurrent", help="run bounded concurrent provider-free qualification")
    qualification.add_argument("--root", type=Path, required=True); qualification.add_argument("--count", type=int, default=2)
    workflow = commands.add_parser("workflow", help="start, resume, or inspect an approved local fake-agent workflow")
    workflow_commands = workflow.add_subparsers(dest="workflow_action", required=True)
    for action in ("start", "resume", "status"):
        item = workflow_commands.add_parser(action)
        item.add_argument("--graph", type=Path, required=True)
        item.add_argument("--state-dir", type=Path, required=True)
        item.add_argument("--max-parallel", type=int, default=1)
        item.add_argument("--worktree", action="append", default=[], metavar="KEY=PATH")
        item.add_argument("--owner", default="WRK-AR0136-LOCAL")
    run_ops = commands.add_parser("run-ops", help="operate and inspect a revision/lease-fenced run journal")
    run_ops_commands = run_ops.add_subparsers(dest="run_ops_action", required=True)
    ops_start = run_ops_commands.add_parser("start", help="create the durable operator record for a run")
    ops_start.add_argument("--state-file", type=Path, required=True); ops_start.add_argument("--binding", type=Path, required=True); ops_start.add_argument("--operation-id", required=True)
    for action in ("status", "follow", "diagnose", "export-evidence"):
        item = run_ops_commands.add_parser(action)
        item.add_argument("--state-file", type=Path, required=True); item.add_argument("--run-id", required=True)
        if action == "follow": item.add_argument("--after-sequence", type=int, default=0)
    for action in ("interrupt", "resume", "cancel", "observe", "recover"):
        item = run_ops_commands.add_parser(action)
        item.add_argument("--state-file", type=Path, required=True); item.add_argument("--run-id", required=True); item.add_argument("--operation-id", required=True)
        item.add_argument("--expected-revision", type=int, required=True); item.add_argument("--lease-id", required=True); item.add_argument("--lease-fence", type=int, required=True)
        item.add_argument("--observation", type=Path); item.add_argument("--artifacts", type=Path); item.add_argument("--accounting-delta", type=int, default=0)
    host = commands.add_parser("host-run", help="run one bounded local worker process")
    host.add_argument("--root", type=Path, required=True); host.add_argument("--cwd", type=Path, required=True)
    host.add_argument("--timeout", type=float, default=5.0); host.add_argument("--output-limit", type=int, default=16384)
    host.add_argument("--allow-env", action="append", default=[]); host.add_argument("--env", action="append", default=[])
    host.add_argument("--allow-network", action="store_true"); host.add_argument("argv", nargs=argparse.REMAINDER)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "project-init":
            from .project_bootstrap import bootstrap
            output = bootstrap(args.name, args.organization, args.project, args.state, preview=args.preview)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "board-acceptance":
            from scripts.board_acceptance import run_acceptance
            output = run_acceptance(name=args.name, organization=args.organization,
                                    workspace=args.workspace, umbrella_root=args.umbrella_root,
                                    runtime_root=args.runtime_source)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "local-run":
            from scripts.local_project_workflow import run, validate
            raw = args.manifest.read_bytes()
            record = run(raw, args.expected_revision)
            output = validate(record, args.expected_revision)
            print(json.dumps({"result": output, "record": record}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "project-register":
            from .project_registry import register
            output = register(args.name, args.project, args.state, args.home)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "project-list":
            from .project_registry import list_projects
            output = list_projects(args.home)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "audit-record":
            from .observability import AuditJournal
            output = AuditJournal(args.home).append(event_id=args.event_id, task_id=args.task_id, task_revision=args.task_revision, category=args.category, status=args.status, detail=args.detail)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "audit-status":
            from .observability import AuditJournal
            output = AuditJournal(args.home).status()
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "security-check":
            from .security import check
            output = check(args.home)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "release-verify":
            from .release import verify_artifact
            output = verify_artifact(args.artifact, version=args.version, source_commit=args.source_commit, expected_sha256=args.sha256, rollback_version=args.rollback_version)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command in {"coord-init", "coord-status", "coord-claim"}:
            from .coordinator_local import LocalCoordinator
            store = LocalCoordinator(args.state_file)
            if args.command == "coord-init": output = store.init(args.task_id, args.project_revision, args.worktree_digest, args.session_id)
            elif args.command == "coord-status": output = store.snapshot()
            else: output = store.claim(args.owner, args.expected_revision)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command in {"schedule-submit", "schedule-dispatch", "schedule-complete", "schedule-status"}:
            from .scheduler_local import LocalScheduler
            store = LocalScheduler(args.state_file)
            if args.command == "schedule-submit": output = store.submit(args.job_id, args.project, args.dependency, args.priority)
            elif args.command == "schedule-dispatch": output = store.dispatch(args.worker)
            elif args.command == "schedule-complete": output = store.complete(args.job_id, args.worker, args.lease, args.status)
            else: output = store.status()
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "host-run":
            from .host_supervisor import HostSupervisor
            if not args.argv or args.argv[0] == "--":
                raise CliError("host_argv_invalid")
            supplied = {}
            for item in args.env:
                if "=" not in item: raise CliError("host_environment_invalid")
                key, value = item.split("=", 1); supplied[key] = value
            output = HostSupervisor(args.root).run(args.argv, args.cwd, env=supplied, allowed_env=args.allow_env, timeout_seconds=args.timeout, output_limit=args.output_limit, require_network_disabled=not args.allow_network)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "agent-run":
            from .agent_session import AgentSession
            if not args.argv or args.argv[0] == "--": raise CliError("host_argv_invalid")
            output = AgentSession(args.root, args.session_id, args.adapter, sandboxed=args.sandbox_required).run(args.argv, args.cwd, input_digest=args.input_digest, timeout_seconds=args.timeout)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "authority-admit":
            from .authority_gates import AuthorityGates
            from scripts.local_authority_transport import demo_client
            output = AuthorityGates(demo_client()).admit(task=args.task, revision=args.revision)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "qualify-concurrent":
            from .qualification import run_concurrent
            output = run_concurrent(args.root, args.count)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "workflow":
            from scripts.autonomous_orchestrator import (
                AutonomousOrchestrator, DurableRunJournal, OrchestratorError, load_graph,
            )
            graph = load_graph(args.graph)
            journal_path = args.state_dir / "run.json"
            exists = journal_path.exists()
            if args.workflow_action == "start" and exists:
                raise OrchestratorError("run_already_exists_use_resume")
            if args.workflow_action in {"resume", "status"} and not exists:
                raise OrchestratorError("run_state_missing_start_first")
            if args.workflow_action == "status":
                output = DurableRunJournal(journal_path, graph, args.max_parallel).status()
            else:
                worktrees = {}
                for binding in args.worktree:
                    if "=" not in binding:
                        raise OrchestratorError("worktree_binding_invalid")
                    key, value = binding.split("=", 1)
                    if key in worktrees or not value:
                        raise OrchestratorError("worktree_binding_duplicate_or_empty")
                    worktrees[key] = Path(value)
                root = Path(__file__).resolve().parents[1]
                runner = AutonomousOrchestrator(
                    graph, state_dir=args.state_dir, worktrees=worktrees,
                    registry_spec=root / "specifications" / "agent-registry-v1.json",
                    helper=root / "tests" / "helpers" / "agent_session_helper.py",
                    owner=args.owner, max_parallel=args.max_parallel,
                )
                output = runner.run()
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "run-ops":
            from scripts.run_operations import RunOperations
            board = RunOperations(args.state_file)
            if args.run_ops_action == "start":
                output = board.start(json.loads(args.binding.read_text(encoding="utf-8")), args.operation_id)
            elif args.run_ops_action in {"status", "follow", "diagnose", "export-evidence"}:
                if args.run_ops_action == "status": output = board.status(args.run_id)
                elif args.run_ops_action == "follow": output = board.follow(args.run_id, args.after_sequence)
                elif args.run_ops_action == "diagnose": output = board.diagnose(args.run_id)
                else: output = board.export_evidence(args.run_id)
            else:
                observation = json.loads(args.observation.read_text(encoding="utf-8")) if args.observation else None
                artifacts = json.loads(args.artifacts.read_text(encoding="utf-8")) if args.artifacts else None
                output = board.apply(args.run_ops_action, run_id=args.run_id, operation_id=args.operation_id, expected_revision=args.expected_revision,
                                     lease_id=args.lease_id, lease_fence=args.lease_fence, observation=observation,
                                     accounting_delta=args.accounting_delta, artifacts=artifacts)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command in {"version", "doctor", "install", "repair", "upgrade", "rollback", "uninstall"}:
            from . import __version__
            from .install import doctor, install, rollback, uninstall

            if args.command == "version":
                output = {"status": "ok", "version": __version__}
            elif args.command == "doctor":
                output = doctor(args.home)
            elif args.command in {"install", "repair", "upgrade"}:
                output = install(args.home, repair=args.command == "repair", upgrade=args.command == "upgrade")
            elif args.command == "rollback":
                output = rollback(args.home)
            else:
                output = uninstall(args.home)
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        manifest, revision = _read_manifest(args.manifest)
        if args.command == "validate":
            output = {"status": "valid", "project": manifest["project"]["name"], "project_revision": revision}
        elif args.command == "init":
            output = initialize_mock(manifest, revision, args.workspace)
        else:
            if not re.fullmatch(r"[a-zA-Z0-9._/-]{1,160}", args.workspace) or ".." in args.workspace.split("/"):
                raise CliError("invalid_workspace_label")
            output = make_plan(manifest, revision, args.workspace, args.expected_revision)
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (CliError, ValueError) as exc:
        print(f"awr: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

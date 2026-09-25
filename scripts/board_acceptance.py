#!/usr/bin/env python3
"""One-command complex-project acceptance through the supervised local runtime."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from awr_cli.authority_gates import AuthorityGates
from awr_cli.project_bootstrap import bootstrap
from scripts.autonomous_orchestrator import AutonomousOrchestrator, canonical, digest, graph_digest
from scripts.local_authority_transport import LocalAuthorityClient, LocalAuthorityEndpoint
from scripts.local_authority_bridge import request_envelope
from scripts.durable_coordinator import DurableFakeCoordinator
from scripts.worker_monitor import RecoveryStore

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_UMBRELLA_ORIGIN = "https://github.com/martin-beck/agent-workflow.git"
RUNTIME_ORIGIN = "https://github.com/martin-beck/agent-workflow-runtime.git"
UMBRELLA_COMMIT = "78cff9000086e4fc73ec6a86b259b4f85e29f46b"
UMBRELLA_MANIFEST_SHA256 = "74aa023d504bd2b4d3dc6a00b88c8061263b5366031e14813a873a1edfd551c6"
RUNTIME_RELEASE = "v0.1.8"
RUNTIME_COMMIT = "79b0c25af69c9bd9d8551c8065fb1488fb36ccd5"
PHASES = (
    ("planning", (), "tree-a", "fake-alpha"),
    ("architecture", (), "tree-b", "fake-beta"),
    ("implementation", ("AR-{0}01", "AR-{0}02"), "tree-a", "fake-beta"),
    ("testing", ("AR-{0}03",), "tree-b", "fake-alpha"),
    ("review", ("AR-{0}04",), "tree-a", "fake-beta"),
    ("repair", ("AR-{0}05",), "tree-b", "fake-alpha"),
    ("documentation", ("AR-{0}06",), "tree-a", "fake-beta"),
)


class BoardAcceptanceError(ValueError):
    """The project cannot meet the board's autonomous acceptance contract."""


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", "-C", str(root), *args], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BoardAcceptanceError("release_provenance_unavailable") from exc
    return result.stdout.strip()


def verify_release_provenance(umbrella_root: Path, runtime_root: Path) -> dict[str, Any]:
    umbrella_root = Path(umbrella_root).resolve(strict=True)
    runtime_root = Path(runtime_root).resolve(strict=True)
    manifest_path = umbrella_root / "project-manifest.yaml"
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise BoardAcceptanceError("canonical_umbrella_manifest_missing") from exc
    if hashlib.sha256(raw).hexdigest() != UMBRELLA_MANIFEST_SHA256:
        raise BoardAcceptanceError("canonical_umbrella_manifest_digest_mismatch")
    if (_git(umbrella_root, "remote", "get-url", "origin") != CANONICAL_UMBRELLA_ORIGIN
            or _git(umbrella_root, "rev-parse", "HEAD") != UMBRELLA_COMMIT
            or _git(umbrella_root, "status", "--porcelain")):
        raise BoardAcceptanceError("canonical_umbrella_checkout_mismatch")
    text = raw.decode("utf-8")
    release_match = re.search(r"(?ms)^  runtime_release:\n    repository: ([^\n]+)\n    release: ([^\n]+)\n    commit: ([0-9a-f]{40})\s*$", text)
    if not release_match or release_match.groups() != ("martin-beck/agent-workflow-runtime", RUNTIME_RELEASE, RUNTIME_COMMIT):
        raise BoardAcceptanceError("canonical_runtime_pin_mismatch")
    if _git(runtime_root, "remote", "get-url", "origin") != RUNTIME_ORIGIN:
        raise BoardAcceptanceError("runtime_origin_mismatch")
    if _git(runtime_root, "status", "--porcelain"):
        raise BoardAcceptanceError("runtime_source_not_clean")
    try:
        tag_commit = _git(runtime_root, "rev-parse", f"refs/tags/{RUNTIME_RELEASE}^{{}}")
    except BoardAcceptanceError as exc:
        raise BoardAcceptanceError("runtime_release_tag_missing") from exc
    if tag_commit != RUNTIME_COMMIT:
        raise BoardAcceptanceError("runtime_release_tag_mismatch")
    return {"umbrella_origin": CANONICAL_UMBRELLA_ORIGIN, "umbrella_commit": UMBRELLA_COMMIT,
            "umbrella_manifest_digest": "sha256:" + UMBRELLA_MANIFEST_SHA256,
            "runtime_origin": RUNTIME_ORIGIN, "runtime_release": RUNTIME_RELEASE,
            "runtime_release_commit": RUNTIME_COMMIT, "runtime_under_test_commit": _git(runtime_root, "rev-parse", "HEAD")}


def compile_project_graph(name: str, brief_digest: str, worktree_digests: dict[str, str]) -> dict[str, Any]:
    """Compile the built-in complex-project template; callers cannot supply lifecycle events."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", name):
        raise BoardAcceptanceError("invalid_project_identity")
    suffix = f"{int(hashlib.sha256(name.encode()).hexdigest()[:2], 16) % 90 + 10:02d}"
    prefix = "AR-" + suffix
    tasks = []
    for index, (phase, dependencies, tree, profile) in enumerate(PHASES, 1):
        task_id = f"{prefix}{index:02d}"
        deps = [item.format(suffix) for item in dependencies]
        tasks.append({"id": task_id, "revision": 1, "dependencies": deps,
                      "worktree_key": tree, "worktree_digest": worktree_digests[tree],
                      "profile_id": profile, "action_digest": digest({"phase": phase, "brief": brief_digest}),
                      "max_attempts": 2})
    graph = {"schema_version": 1, "graph_id": "board-" + suffix, "project_key": name,
             "project_revision": brief_digest, "max_parallelism": 2, "tasks": tasks,
             "approval": {"authority": "coordinator", "status": "pending",
                          "decision_id": "PENDING", "graph_digest": ""}}
    graph["approval"]["graph_digest"] = graph_digest(graph)
    return graph


def _local_gates(task_count: int, graph: dict[str, Any]) -> tuple[AuthorityGates, dict[str, Any]]:
    coordinator = LocalAuthorityEndpoint("coordinator", ["approved"] + ["observed"] * task_count)
    awq = LocalAuthorityEndpoint("awq", ["accepted"] * (task_count * 2))
    awg = LocalAuthorityEndpoint("awg", ["requires_ui"] * (task_count * 2))
    ui = LocalAuthorityEndpoint("ui", ["approved"] * (task_count * 2))
    client = LocalAuthorityClient({item.authority: item for item in (coordinator, awq, awg, ui)})
    approval_request = request_envelope("coordinator", "OP-BOARD-GRAPH-APPROVAL", 1,
                                        digest({"graph_digest": graph_digest(graph)}),
                                        task_id=graph["tasks"][0]["id"])
    approval = client.exchange(approval_request,
                              expected_revision=1, required_authority="coordinator")
    if approval["outcome"] != "approved":
        raise BoardAcceptanceError("coordinator_graph_approval_rejected")
    graph["approval"].update(status="approved",
                              decision_id="DEC-" + approval["operation_id"].removeprefix("OP-"))
    return AuthorityGates(client), {"graph": approval, "endpoints": {"coordinator": coordinator,
            "awq": awq, "awg": awg, "ui": ui}}


def run_acceptance(*, name: str, organization: str, workspace: Path,
                   umbrella_root: Path, runtime_root: Path = ROOT) -> dict[str, Any]:
    provenance = verify_release_provenance(umbrella_root, runtime_root)
    workspace = Path(workspace).absolute()
    project, state = workspace / "project", workspace / "state"
    created = bootstrap(name, organization, project, state)
    brief = {"project": name, "organization": organization, "kind": "complex_software_project",
             "phases": [item[0] for item in PHASES], "source_manifest_digest": provenance["umbrella_manifest_digest"]}
    brief_digest = digest(brief)
    project_root = workspace / "worktrees"
    project_root.mkdir(parents=True, exist_ok=False)
    worktrees: dict[str, Path] = {}
    worktree_digests: dict[str, str] = {}
    for key in ("tree-a", "tree-b"):
        path = project_root / key
        path.mkdir()
        worktrees[key] = path
        worktree_digests[key] = digest({"project": brief_digest, "worktree": key})
    graph = compile_project_graph(name, brief_digest, worktree_digests)
    gates, authority_sources = _local_gates(len(graph["tasks"]), graph)
    (state / "generated-task-graph.json").write_bytes(canonical(graph) + b"\n")
    run_state = state / "run"
    first_task = graph["tasks"][0]
    now = [100.0]
    coordinator = DurableFakeCoordinator(run_state / (first_task["id"] + ".coordinator.json"),
                                         clock=lambda: now[0], lease_seconds=45)
    coordinator.initialize(first_task["id"], 1, graph["project_revision"], first_task["worktree_digest"])
    old_claim = coordinator.claim(first_task["id"], 1, "WRK-BOARD-OLD", "OP-BOARD-OLD-CLAIM")
    old_lease = coordinator.acquire_lease(first_task["id"], old_claim["revision"], "WRK-BOARD-OLD",
                                          "SES-" + first_task["id"][3:] + "-0001",
                                          "OP-BOARD-OLD-LEASE")["lease"]
    checkpoint_binding = {"task_id": first_task["id"], "task_revision": 1,
                          "session_id": old_lease["session"], "worktree_digest": first_task["worktree_digest"],
                          "worker_id": "WRK-BOARD-OLD", "lease_id": old_lease["id"],
                          "lease_fence": old_lease["fence"]}
    RecoveryStore(run_state / "evidence" / (old_lease["session"] + ".checkpoint.json")).checkpoint(
        checkpoint_binding, {"completed_frames": 1})
    now[0] += 46
    runner = AutonomousOrchestrator(graph, state_dir=state / "run", worktrees=worktrees,
            registry_spec=ROOT / "specifications/agent-registry-v1.json",
            helper=ROOT / "tests/helpers/agent_session_helper.py",
            owner="WRK-BOARD-" + hashlib.sha256(name.encode()).hexdigest()[:12].upper(),
            max_parallel=2, lease_seconds=45, authority_gates=gates, clock=lambda: now[0])
    result = runner.run()
    expected = {item["id"] for item in graph["tasks"]}
    authority_records = [json.loads((state / "run" / (task_id + ".authority.json")).read_text())
                         for task_id in sorted(expected)]
    if set(result["tasks"]) != expected or set(result["tasks"].values()) != {"completed"}:
        raise BoardAcceptanceError("autonomous_run_not_accepted")
    if not all(runner._has_complete_gate_record(item, 1) for item in expected):
        raise BoardAcceptanceError("authority_evidence_incomplete")
    graph_path = state / "generated-task-graph.json"
    run_path = state / "run" / "run.json"
    sessions = sorted((state / "run" / "evidence").glob("SES-*-F*.json"))
    if len(sessions) != len(expected):
        raise BoardAcceptanceError("session_evidence_incomplete")
    session_records = [json.loads(path.read_text()) for path in sessions]
    if any(item["terminal"].get("process_tree_clean") is not True for item in session_records):
        raise BoardAcceptanceError("worker_process_not_reaped")
    before_replay = {path.relative_to(state / "run").as_posix(): path.read_bytes()
                     for path in (state / "run").rglob("*.json")}
    replayed = runner.run()
    after_replay = {path.relative_to(state / "run").as_posix(): path.read_bytes()
                    for path in (state / "run").rglob("*.json")}
    if replayed != result or before_replay != after_replay:
        raise BoardAcceptanceError("restart_replay_changed_terminal_state")
    final_state = json.loads(run_path.read_text())
    recoveries = sum(event["status"] == "recovering" for event in final_state["events"])
    if recoveries < 1:
        raise BoardAcceptanceError("recovery_path_not_exercised")
    accounting = {"tasks": len(expected), "sessions": len(sessions), "recoveries": recoveries,
                  "runtime_events": len(final_state["events"]),
                  "authorities": {name: len(source.requests) for name, source in authority_sources["endpoints"].items()}}
    evidence = {"schema_version": 1, "status": "accepted", "project": name,
                "project_binding_digest": created["binding_digest"], "brief_digest": brief_digest,
                "acceptance_spec_digest": digest((ROOT / "specifications/autonomous-board-acceptance-v1.json").read_bytes()),
                "release_provenance": provenance, "graph_digest": graph_digest(graph),
                "graph_evidence_digest": digest(graph_path.read_bytes()),
                "run_evidence_digest": digest(run_path.read_bytes()),
                "authority_evidence_digest": digest({"graph_approval": authority_sources["graph"],
                                                       "task_authorities": authority_records}),
                "graph_approval_digest": digest(authority_sources["graph"]), "accounting": accounting,
                "provider": "not_performed", "credentials": "not_inspected", "network": "disabled",
                "reconciliation": "all_tasks_done", "remote_verification": "unverified"}
    evidence["evidence_digest"] = digest(evidence)
    evidence_path = state / "board-evidence.json"
    evidence_path.write_bytes(canonical(evidence) + b"\n")
    return {"status": "accepted", "project": name, "task_count": len(expected),
            "session_count": len(sessions), "evidence": str(evidence_path),
            "evidence_digest": evidence["evidence_digest"], "release": provenance["runtime_release"],
            "runtime_release_commit": provenance["runtime_release_commit"]}


def verify_evidence(record: dict[str, Any]) -> dict[str, Any]:
    fields = {"schema_version", "status", "project", "project_binding_digest", "brief_digest",
              "acceptance_spec_digest", "release_provenance", "graph_digest", "graph_evidence_digest",
              "run_evidence_digest", "authority_evidence_digest", "graph_approval_digest", "accounting",
              "provider", "credentials", "network", "reconciliation", "remote_verification", "evidence_digest"}
    if not isinstance(record, dict) or set(record) != fields or record.get("schema_version") != 1 or record.get("status") != "accepted":
        raise BoardAcceptanceError("evidence_shape_invalid")
    provenance_fields = {"umbrella_origin", "umbrella_commit", "umbrella_manifest_digest", "runtime_origin",
                         "runtime_release", "runtime_release_commit", "runtime_under_test_commit"}
    accounting_fields = {"tasks", "sessions", "recoveries", "runtime_events", "authorities"}
    if (not isinstance(record["release_provenance"], dict)
            or set(record["release_provenance"]) != provenance_fields
            or not isinstance(record["accounting"], dict)
            or set(record["accounting"]) != accounting_fields
            or set(record["accounting"]["authorities"]) != {"coordinator", "awq", "awg", "ui"}
            or any(type(record["accounting"][key]) is not int or record["accounting"][key] < 0
                   for key in ("tasks", "sessions", "recoveries", "runtime_events"))
            or record["provider"] != "not_performed" or record["credentials"] != "not_inspected"
            or record["network"] != "disabled" or record["remote_verification"] != "unverified"):
        raise BoardAcceptanceError("evidence_projection_invalid")
    evidence_digest = record.get("evidence_digest")
    body = {key: value for key, value in record.items() if key != "evidence_digest"}
    if evidence_digest != digest(body) or record.get("reconciliation") != "all_tasks_done":
        raise BoardAcceptanceError("evidence_digest_or_terminal_state_invalid")
    return {"status": "verified", "evidence_digest": evidence_digest}

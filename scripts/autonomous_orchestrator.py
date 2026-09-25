#!/usr/bin/env python3
"""Durable graph scheduler composing fenced local fake-agent sessions and gates."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from awr_cli.agent_registry import AdapterProfile, AdapterRegistry
from scripts.durable_coordinator import AuthorityError, DurableFakeCoordinator
from scripts.execution_controller import ExecutionBinding, ExecutionController
from scripts.host_sandbox import SandboxBudget
from scripts.interactive_session import InteractionBinding, InteractiveSession, replay
from scripts.worker_control_loop import (
    SPECIFICATION_DIGEST, TEST_CONTRACT_DIGEST, DecisionJournal, Proposal,
    check as check_worker_result, fake_loop,
)

SPEC_PATH = Path(__file__).resolve().parents[1] / "specifications" / "autonomous-orchestrator-v1.json"
WORKFLOW_SPEC_DIGEST = "sha256:" + hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest()
ZERO = "sha256:" + "0" * 64
TASK_ID = re.compile(r"^AR-[0-9]{4}$")
KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TERMINAL = {"completed", "blocked", "failed"}


class OrchestratorError(ValueError):
    """Invalid graph, durable state, lease, or gate outcome."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def graph_digest(graph: dict[str, Any]) -> str:
    return digest({key: value for key, value in graph.items() if key != "approval"})


def validate_graph(graph: Any, max_parallel: int) -> dict[str, dict[str, Any]]:
    fields = {"schema_version", "graph_id", "project_key", "project_revision", "max_parallelism", "tasks", "approval"}
    if not isinstance(graph, dict) or set(graph) != fields or graph["schema_version"] != 1:
        raise OrchestratorError("graph_shape_invalid")
    if not isinstance(graph["graph_id"], str) or not KEY.fullmatch(graph["graph_id"]):
        raise OrchestratorError("graph_id_invalid")
    if not isinstance(graph["project_key"], str) or not KEY.fullmatch(graph["project_key"]):
        raise OrchestratorError("project_key_invalid")
    if not isinstance(graph["project_revision"], str) or not DIGEST.fullmatch(graph["project_revision"]):
        raise OrchestratorError("project_revision_invalid")
    if type(max_parallel) is not int or max_parallel < 1 or max_parallel > 8:
        raise OrchestratorError("operator_parallelism_invalid")
    if type(graph["max_parallelism"]) is not int or not 1 <= graph["max_parallelism"] <= 8:
        raise OrchestratorError("graph_parallelism_invalid")
    approval = graph["approval"]
    if (not isinstance(approval, dict) or set(approval) != {"authority", "status", "decision_id", "graph_digest"}
            or approval["authority"] != "coordinator" or approval["status"] != "approved"
            or not isinstance(approval["decision_id"], str) or not re.fullmatch(r"DEC-[A-Z0-9-]{1,48}", approval["decision_id"])
            or approval["graph_digest"] != graph_digest(graph)):
        raise OrchestratorError("graph_approval_invalid")
    raw = graph["tasks"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= 128:
        raise OrchestratorError("task_count_invalid")
    tasks: dict[str, dict[str, Any]] = {}
    required = {"id", "revision", "dependencies", "worktree_key", "worktree_digest", "profile_id", "action_digest", "max_attempts"}
    for task in raw:
        if not isinstance(task, dict) or set(task) != required:
            raise OrchestratorError("task_shape_invalid")
        if not isinstance(task["id"], str) or not TASK_ID.fullmatch(task["id"]) or task["id"] in tasks:
            raise OrchestratorError("task_identity_invalid")
        if type(task["revision"]) is not int or task["revision"] < 1:
            raise OrchestratorError("task_revision_invalid")
        if type(task["max_attempts"]) is not int or not 1 <= task["max_attempts"] <= 3:
            raise OrchestratorError("task_attempt_budget_invalid")
        if not isinstance(task["dependencies"], list) or len(task["dependencies"]) > 32 or len(set(task["dependencies"])) != len(task["dependencies"]):
            raise OrchestratorError("dependencies_invalid")
        if not isinstance(task["worktree_key"], str) or not KEY.fullmatch(task["worktree_key"]):
            raise OrchestratorError("worktree_key_invalid")
        for field in ("worktree_digest", "action_digest"):
            if not isinstance(task[field], str) or not DIGEST.fullmatch(task[field]):
                raise OrchestratorError(field + "_invalid")
        if task["profile_id"] not in {"fake-alpha", "fake-beta"}:
            raise OrchestratorError("only_deterministic_fake_profiles_are_supported")
        tasks[task["id"]] = dict(task)
    for task in tasks.values():
        if any(dep not in tasks or dep == task["id"] for dep in task["dependencies"]):
            raise OrchestratorError("dependency_reference_invalid")
    visiting: set[str] = set(); visited: set[str] = set()
    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise OrchestratorError("dependency_cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for parent in tasks[task_id]["dependencies"]:
            visit(parent)
        visiting.remove(task_id); visited.add(task_id)
    for task_id in tasks:
        visit(task_id)
    return tasks


class DurableRunJournal:
    """Atomic, fsynced, hash-linked run state safe for concurrent workers."""
    def __init__(self, path: Path, graph: dict[str, Any], max_parallel: int):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        if self.path.is_symlink() or self.lock_path.is_symlink():
            raise OrchestratorError("journal_symlink_rejected")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.graph = graph
        self.graph_hash = graph_digest(graph)
        self.tasks = validate_graph(graph, max_parallel)
        self.max_parallel = min(max_parallel, graph["max_parallelism"])
        self.thread_lock = threading.RLock()
        with self._locked():
            if self.path.exists():
                self._load()
            else:
                self._save({"schema_version": 1, "graph_digest": self.graph_hash, "max_parallelism": self.max_parallel,
                            "events": [], "task_status": {key: "planned" for key in self.tasks}})

    def _locked(self):
        journal = self
        class Lock:
            def __enter__(self):
                journal.lock_path.parent.mkdir(parents=True, exist_ok=True)
                self.handle = journal.lock_path.open("a+"); fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                return self
            def __exit__(self, *_):
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN); self.handle.close()
        return Lock()

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise OrchestratorError("journal_unreadable") from exc
        if (not isinstance(value, dict) or value.get("schema_version") != 1
                or value.get("graph_digest") != self.graph_hash or value.get("max_parallelism") != self.max_parallel
                or set(value.get("task_status", {})) != set(self.tasks)):
            raise OrchestratorError("journal_binding_mismatch")
        previous = ZERO
        allowed = {"planned", "ready", "leased", "executing", "streaming", "evidence_pending", "quality_pending", "guidance_pending", "ui_pending", "repair_pending", "recovering", *TERMINAL}
        for index, event in enumerate(value.get("events", []), 1):
            body = {k: v for k, v in event.items() if k != "event_digest"}
            if (event.get("sequence") != index or event.get("previous_digest") != previous
                    or event.get("event_digest") != digest(body) or event.get("task_id") not in self.tasks
                    or event.get("status") not in allowed or set(event) != {"sequence", "previous_digest", "task_id", "status", "evidence_digest", "event_digest"}
                    or not DIGEST.fullmatch(str(event.get("evidence_digest", "")))):
                raise OrchestratorError("journal_integrity_failure")
            previous = event["event_digest"]
        derived = {key: "planned" for key in self.tasks}
        for event in value["events"]:
            derived[event["task_id"]] = event["status"]
        if derived != value["task_status"]:
            raise OrchestratorError("journal_state_projection_mismatch")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=".awr-run-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(value) + b"\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            directory = os.open(self.path.parent, os.O_DIRECTORY); os.fsync(directory); os.close(directory)
        finally:
            if os.path.exists(temp_name): os.unlink(temp_name)

    def status(self) -> dict[str, Any]:
        with self._locked():
            value = self._load()
            return {"graph_digest": self.graph_hash, "max_parallelism": self.max_parallel,
                    "tasks": dict(value["task_status"]), "events": len(value["events"]),
                    "provider": "not_performed", "credentials": "not_inspected", "remote_verification": "unverified"}

    def transition(self, task_id: str, status: str, evidence: Any) -> None:
        if status not in {"planned", "ready", "leased", "executing", "streaming", "evidence_pending", "quality_pending", "guidance_pending", "ui_pending", "repair_pending", "recovering", *TERMINAL}:
            raise OrchestratorError("unknown_lifecycle_state")
        evidence_digest = digest(evidence)
        with self._locked():
            value = self._load()
            if task_id not in self.tasks:
                raise OrchestratorError("unknown_task")
            prior = value["task_status"][task_id]
            if prior in TERMINAL:
                if prior == status:
                    return
                raise OrchestratorError("terminal_task_replay")
            if prior == status:
                return
            next_states = {
                "planned": {"ready", "failed", "blocked"},
                "ready": {"leased", "recovering", "failed", "blocked"},
                "leased": {"executing", "recovering", "failed", "blocked"},
                "executing": {"streaming", "recovering", "repair_pending", "failed", "blocked"},
                "streaming": {"evidence_pending", "recovering", "repair_pending", "failed", "blocked"},
                "evidence_pending": {"quality_pending", "recovering", "failed", "blocked"},
                "quality_pending": {"guidance_pending", "repair_pending", "recovering", "failed", "blocked"},
                "guidance_pending": {"ui_pending", "repair_pending", "failed", "blocked"},
                "ui_pending": {"completed", "repair_pending", "failed", "blocked"},
                "repair_pending": {"ready", "leased", "failed", "blocked"},
                "recovering": {"leased", "failed", "blocked"},
            }
            if status not in next_states.get(prior, set()):
                raise OrchestratorError("invalid_lifecycle_transition")
            body = {"sequence": len(value["events"]) + 1, "previous_digest": value["events"][-1]["event_digest"] if value["events"] else ZERO,
                    "task_id": task_id, "status": status, "evidence_digest": evidence_digest}
            value["events"].append({**body, "event_digest": digest(body)})
            value["task_status"][task_id] = status
            self._save(value)

    def attempts(self, task_id: str) -> int:
        with self._locked():
            value = self._load()
            return sum(1 for event in value["events"] if event["task_id"] == task_id and event["status"] == "leased")


class AutonomousOrchestrator:
    """Run approved DAG nodes only through Coordinator, fake session, and gates."""
    def __init__(self, graph: dict[str, Any], *, state_dir: Path, worktrees: dict[str, Path],
                 registry_spec: Path, helper: Path, owner: str, max_parallel: int,
                 lease_seconds: int = 45, clock=time.time,
                 gate_outcomes: tuple[str, str, str] = ("approved", "approved", "approved")):
        self.tasks = validate_graph(graph, max_parallel)
        self.graph = graph
        self.state_dir = Path(state_dir).absolute(); self.state_dir.mkdir(parents=True, exist_ok=True)
        self.worktrees = {key: Path(path).resolve(strict=True) for key, path in worktrees.items()}
        # The first integrated loop deliberately selects the built-in sandboxed
        # deterministic profile. No external registry/provider is consulted.
        self.registry = AdapterRegistry(self.state_dir / "agent-registry.json")
        if self.registry.revision == 0:
            for profile_id in ("fake-alpha", "fake-beta"):
                self.registry.register(AdapterProfile(
                    profile_id, "1.0.0", ("deterministic-agent",),
                    frozenset({"request", "stream", "close"}), ("start", "request", "stream", "close"),
                    {"max_request_bytes": 4096, "max_output_events": 4}, True,
                ))
        self.owner = owner
        if not re.fullmatch(r"WRK-[A-Z0-9-]{1,63}", owner):
            raise OrchestratorError("worker_identity_invalid")
        if type(lease_seconds) is not int or not 10 <= lease_seconds <= 300:
            raise OrchestratorError("lease_duration_invalid")
        self.lease_seconds = lease_seconds; self.clock = clock
        if (not isinstance(gate_outcomes, tuple) or len(gate_outcomes) != 3
                or any(item not in {"approved", "rejected", "escalated", "cancelled"} for item in gate_outcomes)):
            raise OrchestratorError("gate_outcomes_invalid")
        self.gate_outcomes = gate_outcomes
        self.journal = DurableRunJournal(self.state_dir / "run.json", graph, max_parallel)
        if set(self.worktrees) != {task["worktree_key"] for task in self.tasks.values()}:
            raise OrchestratorError("worktree_map_mismatch")
        if any(not root.is_dir() for root in self.worktrees.values()):
            raise OrchestratorError("worktree_invalid")

    def run(self) -> dict[str, Any]:
        while True:
            snapshot = self.journal.status()["tasks"]
            pending = [key for key, state in snapshot.items() if state not in TERMINAL]
            if not pending:
                break
            ready = [key for key in self.tasks if snapshot[key] in {"planned", "ready", "repair_pending", "recovering", "leased", "executing", "streaming", "evidence_pending", "quality_pending", "guidance_pending", "ui_pending"}
                     and all(snapshot[dep] == "completed" for dep in self.tasks[key]["dependencies"])]
            if not ready:
                self._block_dependency_failures(snapshot)
                break
            # A worktree is exclusive even when the approved graph has other
            # independent nodes. Different keys may run concurrently.
            selected = []
            keys = set()
            for candidate in ready:
                worktree_key = self.tasks[candidate]["worktree_key"]
                if worktree_key in keys:
                    continue
                selected.append(candidate); keys.add(worktree_key)
                if len(selected) == self.journal.max_parallel:
                    break
            ready = selected
            for task_id in ready:
                if snapshot[task_id] == "planned":
                    self.journal.transition(task_id, "ready", {"graph_digest": graph_digest(self.graph)})
            deferred = False
            with ThreadPoolExecutor(max_workers=self.journal.max_parallel, thread_name_prefix="awr-worker") as pool:
                futures = {pool.submit(self._run_task, task_id): task_id for task_id in ready}
                for future in as_completed(futures):
                    task_id = futures[future]
                    try:
                        future.result()
                    except OrchestratorError as exc:
                        if str(exc) == "active_lease_recovery_deferred":
                            deferred = True
                            continue
                        deferred |= self._recover_or_fail(task_id, exc)
                    except Exception as exc:
                        deferred |= self._recover_or_fail(task_id, exc)
            if deferred:
                break
        return self.journal.status()

    def _recover_or_fail(self, task_id: str, error: Exception) -> bool:
        """Keep a live lease recoverable; reconcile bounded exhaustion truthfully."""
        current = self.journal.status()["tasks"][task_id]
        if current in TERMINAL:
            return False
        coordinator_path = self.state_dir / (task_id + ".coordinator.json")
        if coordinator_path.exists():
            try:
                raw = json.loads(coordinator_path.read_text(encoding="utf-8"))
                task_state = raw["task"]
                # Coordinator may have committed the terminal CAS while its
                # response was lost. Recover success only when the durable
                # authority and all three revision-bound gate decisions agree.
                if (task_state.get("status") == "done"
                        and self._has_complete_gate_record(task_id, self.tasks[task_id]["revision"])):
                    self.journal.transition(task_id, "completed", {
                        "coordinator_status": "done", "recovered_terminal": True,
                    })
                    return False
                lease = task_state.get("lease")
                if task_state.get("status") == "running" and isinstance(lease, dict):
                    coord = DurableFakeCoordinator(coordinator_path, clock=self.clock, lease_seconds=self.lease_seconds)
                    if self.journal.attempts(task_id) >= self.tasks[task_id]["max_attempts"]:
                        latest = coord.read_task(task_id)
                        failed = coord.append_session_event(task_id, latest["revision"], lease, lease["session"],
                            "session_failed", digest({"error_type": type(error).__name__}), f"OP-{lease['session']}-FAILED")
                        coord.reconcile(task_id, failed["revision"], lease, "failed", f"OP-{lease['session']}-FAIL")
                        self.journal.transition(task_id, "failed", {"error_type": type(error).__name__, "attempts_exhausted": True})
                        return False
                    self.journal.transition(task_id, "recovering", {"error_type": type(error).__name__, "fence": lease["fence"]})
                    return True
            except (OSError, ValueError, KeyError, AuthorityError, OrchestratorError):
                pass
        if current not in TERMINAL:
            self.journal.transition(task_id, "failed", {"error_type": type(error).__name__})
        return False

    def _block_dependency_failures(self, snapshot: dict[str, str]) -> None:
        for task_id, status in snapshot.items():
            if status in TERMINAL:
                continue
            if any(snapshot[dep] in {"blocked", "failed"} for dep in self.tasks[task_id]["dependencies"]):
                self.journal.transition(task_id, "blocked", {"reason": "dependency_not_completed"})

    def _run_task(self, task_id: str) -> None:
        task = self.tasks[task_id]
        root = self.worktrees[task["worktree_key"]]
        coord_path = self.state_dir / (task_id + ".coordinator.json")
        coord = DurableFakeCoordinator(coord_path, clock=self.clock, lease_seconds=self.lease_seconds)
        if not coord_path.exists():
            coord.initialize(task_id, task["revision"], self.graph["project_revision"], task["worktree_digest"])
        controller = ExecutionController(registry=self.registry, evidence_dir=self.state_dir / "evidence",
                                         coordinator=coord, owner_id=self.owner, clock=self.clock)
        current = coord.read_task(task_id)
        recovered_lease = None
        if current["status"] in {"done", "blocked", "failed"}:
            # Reconcile may have committed immediately before a process crash.
            if current["status"] == "done" and self._has_complete_gate_record(task_id, task["revision"]):
                self.journal.transition(task_id, "completed", {"coordinator_status": "done", "recovered_terminal": True})
                return
            raise OrchestratorError("coordinator_task_not_runnable")
        if current["status"] == "running":
            self.journal.transition(task_id, "recovering", {"prior_fence": current["lease"]["fence"]})
            if current["lease"]["expires_at"] > self.clock():
                raise OrchestratorError("active_lease_recovery_deferred")
            if self.journal.attempts(task_id) >= task["max_attempts"]:
                raise OrchestratorError("retry_budget_exhausted")
            session_id = current["lease"]["session"]
            checkpoint_path = self.state_dir / "evidence" / f"{session_id}.checkpoint.json"
            recovered = controller.recover(task_id=task_id, session_id=session_id, owner_id=self.owner,
                                           checkpoint_path=checkpoint_path,
                                           attempts=max(0, self.journal.attempts(task_id) - 1))
            recovered_lease = recovered["lease"]
            current = coord.read_task(task_id)
        elif current["status"] == "open":
            session_id = f"SES-{task_id[3:]}-{current['fence'] + 1:04d}"
        else:
            raise OrchestratorError("coordinator_task_not_runnable")
        binding = ExecutionBinding(task_id, task["revision"], self.graph["project_key"],
                                   self.graph["project_revision"], task["worktree_key"],
                                   task["worktree_digest"], session_id)
        admission = {"status": "admitted", "task": task_id, "task_revision": task["revision"],
                     "authority_state": "observed_only", "mandatory_order": ["coordinator", "awq", "awg", "ui"],
                     "decision": "approved", "trace": [{"authority": name, "mode": "deterministic_local_fake"}
                                                              for name in ("coordinator", "awq", "awg", "ui")]}
        def observe_lease(lease, _revision):
            self.journal.transition(task_id, "leased", {"lease_id": lease["id"], "fence": lease["fence"]})
            self.journal.transition(task_id, "executing", {"session_id": session_id})
        execution = controller.run(binding=binding, authority_admission=admission, worktree=root,
                                  adapter_id=task["profile_id"], registry_revision=self.registry.revision,
                                  request_digest=task["action_digest"],
                                  budget=SandboxBudget(timeout_seconds=min(10, self.lease_seconds - 2)),
                                  reconcile_terminal=False, lease_observer=observe_lease,
                                  recovered_lease=recovered_lease)
        if execution["status"] != "completed":
            latest = coord.read_task(task_id)
            coord.reconcile(task_id, latest["revision"], execution["coordinator_lease"], "failed",
                            f"OP-{session_id}-F{execution['coordinator_lease']['fence']}-EXECUTION-FAILED")
            self.journal.transition(task_id, "failed", {"execution_status": execution["status"]})
            return
        self.journal.transition(task_id, "streaming", {"terminal_digest": execution["terminal"]["stdout_digest"]})
        lease_value = execution["coordinator_lease"]
        interactive = InteractiveSession(
            InteractionBinding(session_id, task["revision"], lease_value["id"], lease_value["fence"]),
            protocol=task["profile_id"], lease_expires_at=execution["lease_expires_at"], clock=self.clock,
        )
        correlation = f"COR-{task_id[3:]}-1"
        interactive.input({"session_id": session_id, "task_revision": task["revision"],
                           "lease_id": lease_value["id"], "lease_fence": lease_value["fence"],
                           "correlation_id": correlation, "prompt": task["action_digest"],
                           "deadline": min(self.clock() + 10, execution["lease_expires_at"])})
        for stream_name in ("stdout", "stderr"):
            for frame in execution[stream_name].splitlines():
                if frame:
                    interactive.feed(stream_name, frame)
        interactive.end_turn(correlation)
        interactive.close("completed")
        normalized = replay(interactive.events)
        evidence_digest = digest({"execution": execution["terminal"],
                                  "interaction_events": [event["event_digest"] for event in normalized]})
        latest = coord.read_task(task_id)
        event_receipt = coord.append_session_event(task_id, latest["revision"], lease_value, session_id,
                                                    "interaction_completed", evidence_digest,
                                                    f"OP-{session_id}-F{lease_value['fence']}-INTERACTION")
        self.journal.transition(task_id, "evidence_pending", {"evidence_digest": evidence_digest, "event_count": len(normalized)})
        self.journal.transition(task_id, "quality_pending", {"evidence_digest": evidence_digest})
        decision_journal = DecisionJournal(self.state_dir / (task_id + ".decisions.jsonl"))
        proposal = Proposal(task_id, task["revision"], "execute approved graph action", SPECIFICATION_DIGEST,
                            TEST_CONTRACT_DIGEST, evidence_digest)
        result = fake_loop(outcomes=self.gate_outcomes, journal=decision_journal).run(proposal)
        check_worker_result(result, proposal, decision_journal)
        outcomes = [item["outcome"] for item in result["decisions"]]
        if result["outcome"] != "approved" or [item["authority"] for item in result["decisions"]] != ["awq", "awg", "ui"]:
            latest = coord.read_task(task_id)
            outcome = "blocked" if result["outcome"] == "cancelled" else "failed"
            coord.reconcile(task_id, latest["revision"], lease_value, outcome,
                            f"OP-{session_id}-F{lease_value['fence']}-GATE-REJECTED")
            self.journal.transition(task_id, outcome, {"gate_outcome": result["outcome"]})
            return
        self.journal.transition(task_id, "guidance_pending", {"gate_digest": digest(result["decisions"][:2])})
        self.journal.transition(task_id, "ui_pending", {"gate_digest": digest(result["decisions"])})
        latest = coord.read_task(task_id)
        coord.append_session_event(task_id, latest["revision"], lease_value, session_id,
                                   "workflow_gates_approved", digest(result["decisions"]),
                                   f"OP-{session_id}-F{lease_value['fence']}-GATES-APPROVED")
        latest = coord.read_task(task_id)
        receipt = coord.reconcile(task_id, latest["revision"], lease_value, "done",
                                  f"OP-{session_id}-F{lease_value['fence']}-RECONCILE")
        self.journal.transition(task_id, "completed", {"coordinator_receipt": receipt["receipt_digest"], "evidence_digest": evidence_digest,
                                                          "awq": outcomes[0], "awg": outcomes[1], "ui": outcomes[2]})

    def _has_complete_gate_record(self, task_id: str, revision: int) -> bool:
        path = self.state_dir / (task_id + ".decisions.jsonl")
        if not path.exists():
            return False
        try:
            entries = DecisionJournal(path).entries
            decisions = [entry["decision"] for entry in entries[-3:]]
            return ([item.get("authority") for item in decisions] == ["awq", "awg", "ui"]
                    and all(item.get("task_id") == task_id and item.get("task_revision") == revision
                            and item.get("outcome") == "approved" and item.get("durable") is True for item in decisions))
        except (ValueError, KeyError, TypeError):
            return False

    @staticmethod
    def _coordinator_event(coord, task_id, task_revision, lease, session_id, revision, event):
        try:
            result = coord.append_session_event(task_id, revision, lease, session_id, event["event_type"],
                                                event["event_digest"], f"OP-{session_id}-EV-{event['sequence']:04d}")
        except AuthorityError as exc:
            raise OrchestratorError("coordinator_event_rejected") from exc
        return result["revision"]


def load_graph(path: Path) -> dict[str, Any]:
    try:
        graph = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OrchestratorError("graph_unreadable") from exc
    return graph

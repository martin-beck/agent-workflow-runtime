from __future__ import annotations

import copy
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scripts.autonomous_orchestrator import (
    AutonomousOrchestrator, DurableRunJournal, OrchestratorError, digest, graph_digest,
    validate_graph,
)
from scripts.durable_coordinator import DurableFakeCoordinator
from scripts.worker_monitor import RecoveryStore

ROOT = Path(__file__).resolve().parents[1]


def make_graph(tasks=None):
    graph = {
        "schema_version": 1,
        "graph_id": "fixture-graph",
        "project_key": "awr-fixture",
        "project_revision": digest("project revision"),
        "max_parallelism": 2,
        "tasks": tasks or [
            {"id": "AR-7001", "revision": 1, "dependencies": [], "worktree_key": "tree-a",
             "worktree_digest": digest("tree-a"), "profile_id": "fake-alpha", "action_digest": digest("action-a"), "max_attempts": 2},
            {"id": "AR-7002", "revision": 1, "dependencies": [], "worktree_key": "tree-a",
             "worktree_digest": digest("tree-a"), "profile_id": "fake-beta", "action_digest": digest("action-b"), "max_attempts": 2},
            {"id": "AR-7003", "revision": 1, "dependencies": ["AR-7001", "AR-7002"], "worktree_key": "tree-a",
             "worktree_digest": digest("tree-a"), "profile_id": "fake-alpha", "action_digest": digest("action-c"), "max_attempts": 2},
        ],
        "approval": {"authority": "coordinator", "status": "approved", "decision_id": "DEC-FIXTURE-1", "graph_digest": ""},
    }
    graph["approval"]["graph_digest"] = graph_digest(graph)
    return graph


class AutonomousOrchestratorTests(unittest.TestCase):
    def test_runs_approved_dag_with_real_supervised_fake_sessions_and_all_gates(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            runner = AutonomousOrchestrator(
                make_graph(), state_dir=state, worktrees={"tree-a": ROOT},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py",
                owner="WRK-AR0136-TEST", max_parallel=2,
            )
            result = runner.run()
            self.assertEqual(set(result["tasks"].values()), {"completed"})
            self.assertEqual(result["max_parallelism"], 2)
            self.assertEqual(result["provider"], "not_performed")
            state_a = json.loads((state / "AR-7001.coordinator.json").read_text())
            state_c = json.loads((state / "AR-7003.coordinator.json").read_text())
            self.assertEqual(state_a["task"]["status"], "done")
            self.assertEqual(state_c["task"]["status"], "done")
            history = json.loads((state / "run.json").read_text())["events"]
            completed_inputs = {event["task_id"] for event in history if event["status"] == "completed"}
            ready_c = next(i for i, event in enumerate(history) if event["task_id"] == "AR-7003" and event["status"] == "ready")
            self.assertEqual({event["task_id"] for event in history[:ready_c] if event["status"] == "completed"}, {"AR-7001", "AR-7002"})
            decisions = [json.loads(line)["decision"]["authority"] for line in (state / "AR-7003.decisions.jsonl").read_text().splitlines()]
            self.assertEqual(decisions, ["awq", "awg", "ui"])
            self.assertEqual(DurableRunJournal(state / "run.json", runner.graph, 2).status(), result)

            resumed = AutonomousOrchestrator(
                make_graph(), state_dir=state, worktrees={"tree-a": ROOT},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py",
                owner="WRK-AR0136-TEST", max_parallel=2,
            ).run()
            self.assertEqual(resumed, result)
            self.assertEqual(len(json.loads((state / "run.json").read_text())["events"]), len(history))

    def test_unapproved_changed_cyclic_and_cross_profile_graphs_fail_before_spawn(self):
        good = make_graph()
        for mutate in (
            lambda graph: graph["approval"].update(status="pending"),
            lambda graph: graph["tasks"][0].update(profile_id="codex-agent"),
            lambda graph: graph["tasks"][0].update(dependencies=["AR-7003"]),
        ):
            hostile = copy.deepcopy(good); mutate(hostile)
            with self.subTest(hostile=hostile["approval"]["status"], tasks=hostile["tasks"]), self.assertRaises(OrchestratorError):
                validate_graph(hostile, 2)
        hostile = copy.deepcopy(good); hostile["tasks"][0]["action_digest"] = digest("changed")
        with self.assertRaisesRegex(OrchestratorError, "approval"):
            validate_graph(hostile, 2)
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            with self.assertRaises(OrchestratorError):
                AutonomousOrchestrator(good, state_dir=state, worktrees={"tree-a": ROOT},
                    registry_spec=ROOT / "specifications/agent-registry-v1.json",
                    helper=ROOT / "tests/helpers/agent_session_helper.py", owner="WRK-AR0136-TEST", max_parallel=9)
            self.assertFalse(state.exists())

    def test_journal_tampering_and_operator_completed_state_bypass_are_rejected(self):
        graph = make_graph()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "run.json"
            journal = DurableRunJournal(path, graph, 2)
            with self.assertRaisesRegex(OrchestratorError, "lifecycle"):
                journal.transition("AR-7001", "completed", {"forged": True})
            journal.transition("AR-7001", "ready", {"approved": True})
            raw = json.loads(path.read_text())
            raw["events"][0]["evidence_digest"] = digest("forged")
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(OrchestratorError, "integrity"):
                DurableRunJournal(path, graph, 2).status()

    def test_no_manual_process_arguments_exist_on_operator_interface(self):
        from awr_cli.cli import parser
        with self.assertRaises(SystemExit):
            parser().parse_args(["workflow", "start", "--graph", "g.json", "--state-dir", ".state", "--", "python", "worker.py"])

    def test_rejected_quality_gate_never_reconciles_task_done(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            runner = AutonomousOrchestrator(
                make_graph([make_graph()["tasks"][0]]), state_dir=state, worktrees={"tree-a": ROOT},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py", owner="WRK-AR0136-TEST",
                max_parallel=1, gate_outcomes=("rejected", "approved", "approved"),
            )
            result = runner.run()
            self.assertEqual(result["tasks"]["AR-7001"], "failed")
            task = json.loads((state / "AR-7001.coordinator.json").read_text())["task"]
            self.assertEqual(task["status"], "failed")
            decisions = [json.loads(line)["decision"]["authority"] for line in (state / "AR-7001.decisions.jsonl").read_text().splitlines()]
            self.assertEqual(decisions, ["awq"])

    def test_restart_recovers_expired_coordinator_lease_with_new_fence_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            graph = make_graph([make_graph()["tasks"][0]])
            state.mkdir()
            now = [100.0]
            task = graph["tasks"][0]
            coordinator_path = state / (task["id"] + ".coordinator.json")
            coordinator = DurableFakeCoordinator(coordinator_path, clock=lambda: now[0], lease_seconds=45)
            coordinator.initialize(task["id"], task["revision"], graph["project_revision"], task["worktree_digest"])
            claim = coordinator.claim(task["id"], 1, "WRK-OLD", "OP-OLD-CLAIM")
            session_id = "SES-7001-0001"
            old = coordinator.acquire_lease(task["id"], claim["revision"], "WRK-OLD", session_id, "OP-OLD-LEASE")["lease"]
            checkpoint = state / "evidence" / f"{session_id}.checkpoint.json"
            RecoveryStore(checkpoint).checkpoint({
                "task_id": task["id"], "task_revision": task["revision"], "session_id": session_id,
                "worktree_digest": task["worktree_digest"], "worker_id": "WRK-OLD",
                "lease_id": old["id"], "lease_fence": old["fence"],
            }, {"completed_frames": 1})
            now[0] += 46
            runner = AutonomousOrchestrator(
                graph, state_dir=state, worktrees={"tree-a": ROOT},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py", owner="WRK-AR0136-TEST",
                max_parallel=1, lease_seconds=45, clock=lambda: now[0],
            )
            result = runner.run()
            self.assertEqual(result["tasks"][task["id"]], "completed")
            final = coordinator.read_task(task["id"])
            self.assertEqual(final["status"], "done")
            self.assertGreater(final["fence"], old["fence"])
            self.assertTrue((state / "evidence" / f"{session_id}-F2.json").is_file())

    def test_scheduler_bounds_parallel_workers_and_keeps_each_worktree_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tasks = [
                {"id": "AR-7101", "revision": 1, "dependencies": [], "worktree_key": "tree-a", "worktree_digest": digest("a"), "profile_id": "fake-alpha", "action_digest": digest("a1"), "max_attempts": 2},
                {"id": "AR-7102", "revision": 1, "dependencies": [], "worktree_key": "tree-b", "worktree_digest": digest("b"), "profile_id": "fake-beta", "action_digest": digest("b1"), "max_attempts": 2},
                {"id": "AR-7103", "revision": 1, "dependencies": ["AR-7101"], "worktree_key": "tree-a", "worktree_digest": digest("a"), "profile_id": "fake-alpha", "action_digest": digest("a2"), "max_attempts": 2},
                {"id": "AR-7104", "revision": 1, "dependencies": ["AR-7102"], "worktree_key": "tree-b", "worktree_digest": digest("b"), "profile_id": "fake-beta", "action_digest": digest("b2"), "max_attempts": 2},
            ]
            graph = make_graph(tasks)
            (root / "a").mkdir(); (root / "b").mkdir()
            runner = AutonomousOrchestrator(
                graph, state_dir=root / "state", worktrees={"tree-a": root / "a", "tree-b": root / "b"},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py", owner="WRK-AR0136-TEST", max_parallel=2,
            )
            guard = threading.Lock()
            active = {"count": 0, "peak": 0, "by_worktree": {}}

            def fake_worker(task_id):
                key = runner.tasks[task_id]["worktree_key"]
                with guard:
                    active["count"] += 1
                    active["peak"] = max(active["peak"], active["count"])
                    active["by_worktree"][key] = active["by_worktree"].get(key, 0) + 1
                    self.assertEqual(active["by_worktree"][key], 1)
                for status in ("leased", "executing", "streaming", "evidence_pending", "quality_pending", "guidance_pending", "ui_pending", "completed"):
                    runner.journal.transition(task_id, status, {"test_worker": True})
                    time.sleep(.01)
                with guard:
                    active["count"] -= 1
                    active["by_worktree"][key] -= 1

            runner._run_task = fake_worker
            result = runner.run()
            self.assertEqual(set(result["tasks"].values()), {"completed"})
            self.assertEqual(active["peak"], 2)


if __name__ == "__main__":
    unittest.main()

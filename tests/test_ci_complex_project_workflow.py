"""CI-only end-to-end project run using only deterministic local sessions."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.autonomous_orchestrator import AutonomousOrchestrator, digest, graph_digest
from scripts.durable_coordinator import DurableFakeCoordinator
from scripts.worker_monitor import RecoveryStore

ROOT = Path(__file__).resolve().parents[1]


def project_graph():
    """Describe work; all lifecycle and interaction evidence is produced at runtime."""
    phases = [
        ("7201", "planning", [], "tree-a", "fake-alpha"),
        ("7202", "architecture", [], "tree-b", "fake-beta"),
        ("7203", "implementation", ["AR-7201", "AR-7202"], "tree-a", "fake-beta"),
        ("7204", "testing", ["AR-7203"], "tree-b", "fake-alpha"),
        ("7205", "review", ["AR-7204"], "tree-a", "fake-beta"),
        ("7206", "repair", ["AR-7205"], "tree-b", "fake-alpha"),
        ("7207", "documentation", ["AR-7206"], "tree-a", "fake-beta"),
    ]
    tasks = [{
        "id": "AR-" + suffix, "revision": 1, "dependencies": dependencies,
        "worktree_key": tree, "worktree_digest": digest(tree),
        "profile_id": profile, "action_digest": digest({"phase": phase}),
        "max_attempts": 2,
    } for suffix, phase, dependencies, tree, profile in phases]
    graph = {
        "schema_version": 1, "graph_id": "ci-complex-project",
        "project_key": "awr-ci-project", "project_revision": digest("ci-project-v1"),
        "max_parallelism": 2, "tasks": tasks,
        "approval": {"authority": "coordinator", "status": "approved",
                      "decision_id": "DEC-CI-PROJECT-1", "graph_digest": ""},
    }
    graph["approval"]["graph_digest"] = graph_digest(graph)
    return graph


class CIComplexProjectWorkflowTests(unittest.TestCase):
    def test_framework_runs_concurrent_heterogeneous_project_and_reconciles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tree-a").mkdir()
            (root / "tree-b").mkdir()
            graph = project_graph()
            state = root / "state"
            state.mkdir()
            now = [100.0]
            recovered_task = graph["tasks"][0]
            coordinator = DurableFakeCoordinator(state / "AR-7201.coordinator.json",
                                                   clock=lambda: now[0], lease_seconds=45)
            coordinator.initialize("AR-7201", 1, graph["project_revision"],
                                   recovered_task["worktree_digest"])
            claim = coordinator.claim("AR-7201", 1, "WRK-OLD-CI", "OP-CI-OLD-CLAIM")
            old_lease = coordinator.acquire_lease("AR-7201", claim["revision"], "WRK-OLD-CI",
                                                  "SES-7201-0001", "OP-CI-OLD-LEASE")["lease"]
            checkpoint_binding = {
                "task_id": "AR-7201", "task_revision": 1, "session_id": "SES-7201-0001",
                "worktree_digest": recovered_task["worktree_digest"], "worker_id": "WRK-OLD-CI",
                "lease_id": old_lease["id"], "lease_fence": old_lease["fence"],
            }
            RecoveryStore(state / "evidence/SES-7201-0001.checkpoint.json").checkpoint(
                checkpoint_binding, {"completed_frames": 1})
            now[0] += 46
            runner = AutonomousOrchestrator(
                graph, state_dir=state,
                worktrees={"tree-a": root / "tree-a", "tree-b": root / "tree-b"},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py",
                owner="WRK-CI-PROJECT", max_parallel=2,
                lease_seconds=45, clock=lambda: now[0],
            )
            outcome = runner.run()
            self.assertEqual(set(outcome["tasks"].values()), {"completed"})
            self.assertEqual(outcome["provider"], "not_performed")
            self.assertEqual(outcome["remote_verification"], "unverified")

            first = json.loads((state / "AR-7201.coordinator.json").read_text())
            second = json.loads((state / "AR-7202.coordinator.json").read_text())
            self.assertEqual(first["task"]["status"], "done")
            self.assertEqual(second["task"]["status"], "done")
            self.assertGreater(first["task"]["fence"], 0)
            self.assertGreater(first["task"]["fence"], old_lease["fence"])
            self.assertGreater(second["task"]["fence"], 0)

            sessions = list((state / "evidence").glob("SES-*-F*.json"))
            self.assertEqual(len(sessions), len(graph["tasks"]))
            self.assertTrue((state / "evidence/SES-7201-0001-F2.json").is_file())
            adapters = set()
            for path in sessions:
                record = json.loads(path.read_text())
                spawn, terminal = record["spawn"], record["terminal"]
                adapters.add(spawn["adapter_id"])
                self.assertEqual(spawn["stdio"], {"stdin": "pipe", "stdout": "pipe", "stderr": "pipe"})
                self.assertEqual(spawn["controls"]["network"], True)
                self.assertEqual(terminal["status"], "completed")
                self.assertTrue(terminal["process_tree_clean"])
                self.assertRegex(record["terminal"]["stdout_digest"], r"^sha256:[0-9a-f]{64}$")
                task = next(item for item in graph["tasks"] if item["id"] == spawn["task"])
                response = f"response:COR-{task['id'][3:]}-1:{task['action_digest']}"
                frame = ({"type": "message", "data": {"text": response}}
                         if spawn["adapter_id"] == "fake-alpha" else
                         {"event": "assistant_delta", "payload": {"text": response}})
                serialized = json.dumps(frame, separators=(",", ":")) + "\n"
                self.assertEqual(terminal["stdout_digest"], digest(serialized))
            self.assertEqual(adapters, {"fake-alpha", "fake-beta"})

            history = json.loads((state / "run.json").read_text())["events"]
            self.assertTrue(any(item["status"] == "leased" for item in history))
            self.assertEqual(sum(item["status"] == "completed" for item in history), 7)
            completed_before_second_lease = min(i for i, item in enumerate(history)
                                                 if item["status"] == "completed")
            first_two_leases = [i for i, item in enumerate(history) if item["status"] == "leased"][:2]
            self.assertEqual(len(first_two_leases), 2)
            self.assertTrue(all(i < completed_before_second_lease for i in first_two_leases))
            implementation_ready = next(i for i, item in enumerate(history)
                                         if item["task_id"] == "AR-7203" and item["status"] == "ready")
            self.assertEqual({item["task_id"] for item in history[:implementation_ready]
                              if item["status"] == "completed"}, {"AR-7201", "AR-7202"})
            for suffix in ("7201", "7202", "7203", "7204", "7205", "7206", "7207"):
                decisions = [json.loads(line)["decision"]["authority"] for line in
                             (state / f"AR-{suffix}.decisions.jsonl").read_text().splitlines()]
                self.assertEqual(decisions, ["awq", "awg", "ui"])

            before = {path.name: path.read_bytes() for path in state.glob("*.json")}
            replayed = AutonomousOrchestrator(
                graph, state_dir=state,
                worktrees={"tree-a": root / "tree-a", "tree-b": root / "tree-b"},
                registry_spec=ROOT / "specifications/agent-registry-v1.json",
                helper=ROOT / "tests/helpers/agent_session_helper.py",
                owner="WRK-CI-PROJECT", max_parallel=2,
                lease_seconds=45, clock=lambda: now[0],
            ).run()
            self.assertEqual(replayed, outcome)
            self.assertEqual(before, {path.name: path.read_bytes() for path in state.glob("*.json")})


if __name__ == "__main__":
    unittest.main()

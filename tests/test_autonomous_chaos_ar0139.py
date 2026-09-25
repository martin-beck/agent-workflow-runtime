"""AR-0139 deterministic crash/restart qualification of the autonomous path."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autonomous_orchestrator import AutonomousOrchestrator, OrchestratorError, digest, graph_digest
from scripts.durable_coordinator import DurableFakeCoordinator

ROOT = Path(__file__).resolve().parents[1]


def graph():
    value = {
        "schema_version": 1, "graph_id": "ar0139-chaos",
        "project_key": "awr-chaos", "project_revision": digest("project-r1"),
        "max_parallelism": 2,
        "tasks": [
            {"id": "AR-1391", "revision": 1, "dependencies": [], "worktree_key": "tree-a",
             "worktree_digest": digest("tree-a"), "profile_id": "fake-alpha",
             "action_digest": digest("action-a"), "max_attempts": 2},
            {"id": "AR-1392", "revision": 1, "dependencies": [], "worktree_key": "tree-a",
             "worktree_digest": digest("tree-a"), "profile_id": "fake-beta",
             "action_digest": digest("action-b"), "max_attempts": 2},
        ],
        "approval": {"authority": "coordinator", "status": "approved",
                     "decision_id": "DEC-AR0139", "graph_digest": ""},
    }
    value["approval"]["graph_digest"] = graph_digest(value)
    return value


class AutonomousChaosAR0139Tests(unittest.TestCase):
    def make_runner(self, value, state, tree, now=lambda: 100.0):
        return AutonomousOrchestrator(
            value, state_dir=state, worktrees={"tree-a": tree},
            registry_spec=ROOT / "specifications/agent-registry-v1.json",
            helper=ROOT / "tests/helpers/agent_session_helper.py",
            owner="WRK-AR0139-CHAOS", max_parallel=2, lease_seconds=45,
            clock=now,
        )

    def test_normative_scenario_contract_is_bound_to_claimed_revision(self):
        contract = json.loads((ROOT / "specifications/autonomous-chaos-restart-v1.json").read_text())
        self.assertEqual(contract["task"], {"id": "AR-0139", "revision": 3})
        self.assertTrue(contract["normative"])
        self.assertEqual(contract["execution"]["provider"], "not_performed")
        self.assertEqual(contract["execution"]["credentials"], "not_inspected")
        self.assertEqual(len(contract["scenarios"]), len(set(contract["scenarios"])))
        self.assertTrue(all(item in contract["scenarios"] for item in (
            "worker_process_crash_and_cleanup", "host_or_supervisor_restart",
            "lease_expiry_and_new_fence", "lost_reordered_duplicate_frames",
            "coordinator_cas_timeout_and_ambiguous_write",
            "ui_interruption_and_unresolved_decision",
            "sandbox_denial_and_resource_exhaustion",
            "same_worktree_and_cross_project_contention",
            "checkpoint_accounting_and_replay",
        )))

    def test_repeated_restart_replay_and_same_worktree_contention_accept_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); tree = root / "tree"; tree.mkdir()
            state = root / "state"; value = graph()
            first = self.make_runner(value, state, tree).run()
            self.assertEqual(set(first["tasks"].values()), {"completed"})
            before = {p.name: p.read_bytes() for p in state.glob("*.json")}
            second = self.make_runner(value, state, tree).run()
            third = self.make_runner(value, state, tree).run()
            self.assertEqual(second, first)
            self.assertEqual(third, first)
            self.assertEqual(before, {p.name: p.read_bytes() for p in state.glob("*.json")})
            for task in value["tasks"]:
                authority = json.loads((state / f"{task['id']}.coordinator.json").read_text())
                self.assertEqual(authority["task"]["status"], "done")
                self.assertEqual(sum(e["kind"] == "reconciled" for e in authority["events"]), 1)
                decisions = [json.loads(line)["decision"]["authority"] for line in
                             (state / f"{task['id']}.decisions.jsonl").read_text().splitlines()]
                self.assertEqual(decisions, ["awq", "awg", "ui"])

    def test_lost_terminal_authority_response_recovers_committed_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); tree = root / "tree"; tree.mkdir()
            state = root / "state"; value = graph()
            original = DurableFakeCoordinator.reconcile
            lost = {"done": False}

            def ambiguous_once(coordinator, task_id, revision, lease, status, operation_id):
                if status == "done" and not lost["done"]:
                    coordinator.ambiguous_once = True
                    lost["done"] = True
                return original(coordinator, task_id, revision, lease, status, operation_id)

            with patch.object(DurableFakeCoordinator, "reconcile", ambiguous_once):
                result = self.make_runner(value, state, tree).run()
            self.assertTrue(lost["done"])
            self.assertEqual(set(result["tasks"].values()), {"completed"})
            for task in value["tasks"]:
                authority = json.loads((state / f"{task['id']}.coordinator.json").read_text())
                journal = json.loads((state / "run.json").read_text())
                self.assertEqual(authority["task"]["status"], "done")
                self.assertEqual(journal["task_status"][task["id"]], "completed")
                self.assertEqual(sum(e["kind"] == "reconciled" for e in authority["events"]), 1)

    def test_lost_gate_evidence_cannot_turn_authority_done_into_runtime_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); tree = root / "tree"; tree.mkdir()
            state = root / "state"; value = graph()
            original = AutonomousOrchestrator._has_complete_gate_record
            original_reconcile = DurableFakeCoordinator.reconcile

            def ambiguous_reconcile(coordinator, task_id, revision, lease, status, operation_id):
                if status == "done":
                    coordinator.ambiguous_once = True
                return original_reconcile(coordinator, task_id, revision, lease, status, operation_id)

            def withhold_gate_record(runner, task_id, revision):
                return False if (state / f"{task_id}.decisions.jsonl").exists() else original(runner, task_id, revision)

            # A committed terminal authority state without verifiable local
            # gate evidence is not promoted to success on restart.
            with (patch.object(AutonomousOrchestrator, "_has_complete_gate_record", withhold_gate_record),
                  patch.object(DurableFakeCoordinator, "reconcile", ambiguous_reconcile)):
                result = self.make_runner(value, state, tree).run()
                self.assertNotEqual(set(result["tasks"].values()), {"completed"})

    def test_stale_or_duplicate_terminal_transition_is_rejected(self):
        # Terminal journal rows cannot be rewritten by replayed worker output.
        from scripts.autonomous_orchestrator import DurableRunJournal
        value = graph()
        with tempfile.TemporaryDirectory() as temporary:
            journal = DurableRunJournal(Path(temporary) / "run.json", value, 2)
            with self.assertRaises(OrchestratorError):
                journal.transition("AR-1391", "completed", {"forged": True})


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.autonomous_workflow import WorkflowError, WorkflowState
from scripts.check_autonomous_workflow import CheckError, load_json, validate_record, validate_spec

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/autonomous-workflow-v1.json"
FIXTURE = ROOT / "specifications/fixtures/autonomous-workflow-ar0023-v1.json"


class AutonomousWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.record = load_json(FIXTURE)

    def reject(self, record):
        with self.assertRaises(CheckError):
            validate_record(record)

    def test_positive_end_to_end_trace(self):
        validate_spec(self.spec)
        result = validate_record(self.record)
        self.assertEqual(result["events"], 14)
        self.assertEqual(result["final"], "terminal")
        self.assertEqual(result["remote_verification"], "unverified")

    def test_hostile_stale_replay_order_authority_and_privacy(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["events"][1]["event_id"] = replay["events"][0]["event_id"]; self.reject(replay)
        order = copy.deepcopy(self.record); order["events"][4], order["events"][5] = order["events"][5], order["events"][4]; self.reject(order)
        authority = copy.deepcopy(self.record); authority["events"][3]["authority"] = "runtime"; self.reject(authority)
        privacy = copy.deepcopy(self.record); privacy["events"][0]["payload"]["plan_digest"] = "sha256:" + "a" * 64; privacy["events"][0]["payload"]["prompt"] = "private"; self.reject(privacy)

    def test_hostile_merge_remote_recovery_and_durable_claims(self):
        merge = copy.deepcopy(self.record); merge["events"][11]["payload"]["merge_status"] = "merged"; self.reject(merge)
        remote = copy.deepcopy(self.record); remote["events"][-1]["payload"]["remote_verification"] = "success"; self.reject(remote)
        recovery = copy.deepcopy(self.record); recovery["events"][7]["payload"]["checkpoint_digest"] = "sha256:" + "f" * 64; self.reject(recovery)
        durable = copy.deepcopy(self.record); durable["events"][12]["payload"]["durable_state"] = "mutated"; self.reject(durable)

    def test_model_fences_old_worker_after_recovery(self):
        state = WorkflowState(1, "SES-AR0023-X", "sha256:" + "a" * 64, "WRK-A", "LSE-A")
        common = {"task_revision": 1, "session_id": "SES-AR0023-X", "worktree_digest": "sha256:" + "a" * 64, "worker_id": "WRK-A", "lease_id": "LSE-A"}
        events = [
            ("plan_observed", "coordinator", {"plan_digest": "sha256:" + "1" * 64, "plan_status": "observed"}),
            ("execution_started", "runtime", {"execution_digest": "sha256:" + "2" * 64}),
            ("quality_submitted", "awq", {"evidence_digest": "sha256:" + "3" * 64, "quality_status": "submitted_for_review"}),
            ("oracle_discussion", "awg", {"discussion_digest": "sha256:" + "4" * 64, "oracle_status": "discussion_requested"}),
            ("oracle_decision", "awg", {"decision_digest": "sha256:" + "5" * 64, "decision_status": "approved"}),
            ("checkpoint", "runtime", {"checkpoint_digest": "sha256:" + "6" * 64, "checkpoint_status": "created"}),
            ("interrupt", "runtime", {"reason_digest": "sha256:" + "7" * 64, "interrupt_status": "acknowledged"}),
        ]
        for number, (operation, authority, payload) in enumerate(events):
            state.apply({**common, "event_id": operation, "operation": operation, "authority": authority, "state": state.state, "payload": payload})
        state.apply({**common, "event_id": "recover", "operation": "recover", "authority": "coordinator", "state": "interrupted", "payload": {"checkpoint_digest": "sha256:" + "6" * 64, "new_worker": "WRK-B", "new_lease": "LSE-B", "recovery_status": "fenced"}})
        with self.assertRaises(WorkflowError):
            state.apply({**common, "event_id": "old-resume", "operation": "resume", "authority": "runtime", "state": "recovering", "payload": {"checkpoint_digest": "sha256:" + "6" * 64, "resume_status": "resumed"}})


if __name__ == "__main__":
    unittest.main()

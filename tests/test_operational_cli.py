import copy
import unittest
from pathlib import Path

from scripts.check_operational_cli import CheckError, load, validate_record, validate_spec
from scripts.operational_cli import OperationalError, OperationalState

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/operational-cli-v1.json"
FIXTURE = ROOT / "specifications/fixtures/operational-cli-ar0024-v1.json"

class OperationalCliTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(FIXTURE)

    def reject(self, record=None, revision=3):
        with self.assertRaises(CheckError): validate_record(record or self.record, self.spec, revision)

    def test_positive_trace_is_terminal_and_non_live(self):
        validate_spec(self.spec)
        result = validate_record(self.record, self.spec)
        self.assertEqual(result["commands"], 8)
        self.assertEqual(result["final"], "stopped")
        self.assertEqual(result["durable_state"], "not_performed")
        self.assertEqual(result["remote_verification"], "unverified")

    def test_stale_replay_malformed_and_privacy_fail_closed(self):
        self.reject(revision=4)
        replay = copy.deepcopy(self.record); replay["events"][1]["event_id"] = replay["events"][0]["event_id"]; self.reject(replay)
        crossed = copy.deepcopy(self.record); crossed["events"][0]["session_id"] = "SES-OTHER"; self.reject(crossed)
        private = copy.deepcopy(self.record); private["events"][0]["payload"]["prompt"] = "not allowed"; self.reject(private)
        malformed = copy.deepcopy(self.record); malformed["events"][0]["payload"]["profile"] = "provider"; self.reject(malformed)
        over_budget = copy.deepcopy(self.record); over_budget["events"][0]["payload"]["max_events"] = 1001; self.reject(over_budget)

    def test_interrupt_resume_and_shutdown_guards(self):
        wrong = copy.deepcopy(self.record); wrong["events"][4]["payload"]["checkpoint_digest"] = "sha256:" + "f" * 64; self.reject(wrong)
        unsafe = copy.deepcopy(self.record); unsafe["events"][-1]["payload"]["remote_verification"] = "success"; self.reject(unsafe)
        premature = copy.deepcopy(self.record); premature["events"][-1]["state"] = "observed"; self.reject(premature)

    def test_model_rejects_unauthorized_transition(self):
        state = OperationalState(3, "agent-workflow-runtime", "sha256:" + "a" * 64, "SES")
        event = {"event_id":"RUN","sequence":1,"command":"run","authority":"runtime","state":"new","next_state":"running","task_revision":3,"project":"agent-workflow-runtime","worktree_digest":"sha256:" + "a" * 64,"session_id":"SES","invocation":1,"payload":{"run_digest":"sha256:" + "b" * 64,"run_status":"started"},"evidence_digest":"sha256:" + "c" * 64,"disposition":"observed"}
        with self.assertRaises(OperationalError): state.apply(event)

if __name__ == "__main__": unittest.main()

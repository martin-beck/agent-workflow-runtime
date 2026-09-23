import copy
import unittest
from pathlib import Path

from scripts.check_checkpoint_recovery import CheckError, load_json, validate_spec, validate_trace
from scripts.checkpoint_recovery import RecoveryError, RecoveryState

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/checkpoint-recovery-v1.json"
TRACE = ROOT / "specifications/fixtures/checkpoint-recovery-ar0007-v1.json"


class CheckpointRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)

    def reject(self, trace=None, revision=5):
        with self.assertRaises(CheckError):
            validate_trace(trace or self.trace, self.spec, revision)

    def test_valid_recovery_and_digest_binding(self):
        validate_spec(self.spec)
        result = validate_trace(self.trace, self.spec, 5)
        self.assertEqual(result["final"], "completed")
        self.assertEqual(result["actions"], 7)

    def test_hostile_revision_replay_unknown_and_private_inputs(self):
        self.reject(revision=4)
        stale = copy.deepcopy(self.trace)
        stale["task"]["revision"] = 4
        self.reject(stale)
        replay = copy.deepcopy(self.trace)
        replay["actions"][3]["event_id"] = replay["actions"][2]["event_id"]
        self.reject(replay)
        unknown = copy.deepcopy(self.trace)
        unknown["actions"][0]["payload"]["extra"] = "nope"
        self.reject(unknown)
        private = copy.deepcopy(self.trace)
        private["evidence"]["private_path"] = "/hidden"
        self.reject(private)

    def test_hostile_retry_fence_and_recovery_cases(self):
        changed = copy.deepcopy(self.trace)
        changed["actions"][1]["payload"]["result_digest"] = "sha256:" + "9" * 64
        self.reject(changed)
        old_worker = copy.deepcopy(self.trace)
        old_worker["actions"][4]["worker"] = "WRK-AR0007-A"
        self.reject(old_worker)
        wrong_checkpoint = copy.deepcopy(self.trace)
        wrong_checkpoint["actions"][4]["payload"]["checkpoint_id"] = "CHK-OTHER"
        self.reject(wrong_checkpoint)
        invalid = copy.deepcopy(self.trace)
        invalid["actions"][5]["operation"] = "complete"
        self.reject(invalid)

    def test_model_rejects_recovery_without_verified_checkpoint(self):
        state = RecoveryState(5, "SES-AR0007-X", "agent-workflow-runtime-0007", "WRK-A", "LSE-A")
        state.action("host_failed", event_id="EV-1", worker="WRK-A", lease="LSE-A")
        with self.assertRaises(RecoveryError):
            state.action("recover", event_id="EV-2", worker="WRK-A", lease="LSE-A", payload={"new_worker": "WRK-B", "new_lease": "LSE-B"})


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.check_ui_live_human_gate import load, main
from scripts.ui_live_human_gate import GateError, validate


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/ui-live-human-gate-v1.json"
RECORD = ROOT / "specifications/fixtures/ui-live-human-gate-ar0039-v1.json"


class UiLiveHumanGateTests(unittest.TestCase):
    def setUp(self):
        self.record = load(RECORD)

    def reject(self, record=None, revision=3):
        with self.assertRaises(GateError):
            validate(record or self.record, revision)

    def test_revision_three_fixture_is_resumable_and_authority_neutral(self):
        result = validate(self.record, 3)
        self.assertEqual(result["final"], "safe_exit")
        self.assertTrue(result["resumable"])
        self.assertEqual(self.record["human_gate"]["guidance_status"], "not_decided")
        self.assertEqual(main(["--spec", str(SPEC), "--record", str(RECORD), "--evidence", str(ROOT / "specifications/fixtures/ui-live-human-gate-evidence-ar0039-v1.json"), "--expected-revision", "3"]), 0)

    def test_stale_cross_binding_replay_privacy_and_authority_fail_closed(self):
        self.reject(revision=2)
        crossed = copy.deepcopy(self.record)
        crossed["worktree"]["key"] = "agent-workflow-runtime-0038"
        self.reject(crossed)
        replay = copy.deepcopy(self.record)
        replay["events"][3]["event_id"] = replay["events"][0]["event_id"]
        self.reject(replay)
        private = copy.deepcopy(self.record)
        private["request"]["prompt"] = "not allowed"
        self.reject(private)
        authority = copy.deepcopy(self.record)
        authority["human_gate"]["guidance_status"] = "approved"
        self.reject(authority)

    def test_model_rejects_missing_checkpoint_and_changed_input_digest(self):
        missing = copy.deepcopy(self.record)
        missing["resume"]["checkpoint_event_id"] = "EVT-AR0039-OPEN"
        self.reject(missing)
        changed = copy.deepcopy(self.record)
        changed["human_gate"]["selection_id"] = "ALT-AR0039-TWO"
        self.reject(changed)


if __name__ == "__main__":
    unittest.main()

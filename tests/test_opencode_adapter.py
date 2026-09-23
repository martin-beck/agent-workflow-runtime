import copy
import unittest
from pathlib import Path

from scripts.check_opencode_adapter import ContractError, load_json, validate_replay, validate_spec
from scripts.opencode_adapter import OpenCodeAdapterError, normalize, replay


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications" / "opencode-adapter-v1.json"
REPLAY = ROOT / "specifications" / "fixtures" / "opencode-replay-ar0016-v1.json"


class OpenCodeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.record = load_json(REPLAY)

    def test_spec_and_replay(self):
        validate_spec(load_json(SPEC))
        result = validate_replay(self.record)
        self.assertEqual(result["events"], 6)
        self.assertEqual(result["terminal_event"], "completed")
        self.assertEqual(replay(self.record["native"]), self.record["normalized"])

    def test_mapping_is_explicit_and_bounded(self):
        events = replay(self.record["native"])
        self.assertEqual([event["event_type"] for event in events], ["session_started", "plan_proposed", "tool_call", "tool_call", "file_change", "completed"])
        self.assertEqual([event["disposition"] for event in events], ["accepted", "accepted", "started", "completed", "accepted", "completed"])
        self.assertTrue(all("content" not in event and "output" not in event for event in events))

    def test_hostile_stale_unknown_privacy_and_cross_binding(self):
        stale = copy.deepcopy(self.record["native"])
        stale[0]["task"]["revision"] = 4
        with self.assertRaises(OpenCodeAdapterError):
            replay(stale)
        unknown = copy.deepcopy(self.record["native"])
        unknown[0]["kind"] = "message.raw"
        with self.assertRaises(OpenCodeAdapterError):
            replay(unknown)
        private = copy.deepcopy(self.record["native"])
        private[1]["prompt"] = "must not enter contract"
        with self.assertRaises(OpenCodeAdapterError):
            replay(private)
        cross = copy.deepcopy(self.record["native"])
        cross[2]["session"]["worktree_key"] = "other-worktree"
        with self.assertRaises(OpenCodeAdapterError):
            replay(cross)

    def test_hostile_tamper_replay_and_revision(self):
        tampered = copy.deepcopy(self.record)
        tampered["normalized"][2]["disposition"] = "completed"
        with self.assertRaises(ContractError):
            validate_replay(tampered)
        repeated = copy.deepcopy(self.record["native"])
        repeated[1] = copy.deepcopy(repeated[0])
        repeated[1]["sequence"] = 2
        with self.assertRaises(OpenCodeAdapterError):
            replay(repeated)
        with self.assertRaises(ContractError):
            validate_replay(self.record, expected_revision=6)


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.capability_broker import CapabilityBrokerError
from scripts.check_capability_broker import CheckError, load_json, validate_spec, validate_trace


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/capability-broker-v1.json"
TRACE = ROOT / "specifications/fixtures/capability-broker-ar0019-v1.json"


class CapabilityBrokerTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)

    def assert_rejected(self, trace=None, revision=1):
        with self.assertRaises((CheckError, CapabilityBrokerError)):
            validate_trace(trace or self.trace, self.spec, revision)

    def test_positive_revision_bound_grant_and_tools(self):
        validate_spec(self.spec)
        result = validate_trace(self.trace, self.spec, 1)
        self.assertEqual(result["state"], "active")
        self.assertEqual(result["accepted_actions"], 3)

    def test_stale_revision_is_rejected(self):
        self.assert_rejected(revision=2)
        stale = copy.deepcopy(self.trace)
        stale["task"]["revision"] = 2
        self.assert_rejected(stale)

    def test_replayed_action_is_rejected(self):
        replay = copy.deepcopy(self.trace)
        replay["actions"][2]["id"] = replay["actions"][1]["id"]
        self.assert_rejected(replay)

    def test_unknown_fields_are_rejected(self):
        unknown = copy.deepcopy(self.trace)
        unknown["actions"][0]["unbounded_output"] = "x"
        self.assert_rejected(unknown)

    def test_private_values_are_rejected(self):
        private = copy.deepcopy(self.trace)
        private["evidence"]["private_path"] = "/home/worker/source"
        self.assert_rejected(private)

    def test_cross_worktree_and_cross_project_are_rejected(self):
        worktree = copy.deepcopy(self.trace)
        worktree["actions"][1]["worktree"]["key"] = "other-worktree"
        self.assert_rejected(worktree)
        project = copy.deepcopy(self.trace)
        project["actions"][1]["project"]["key"] = "other-project"
        self.assert_rejected(project)

    def test_unauthorized_and_unknown_tools_are_rejected(self):
        unauthorized = copy.deepcopy(self.trace)
        unauthorized["actions"][0]["tool"] = "network"
        unauthorized["actions"][0]["operation"] = "network"
        self.assert_rejected(unauthorized)
        unknown = copy.deepcopy(self.trace)
        unknown["grant"]["tools"].append({"id": "shell", "version": "1.0.0"})
        self.assert_rejected(unknown)


if __name__ == "__main__":
    unittest.main()

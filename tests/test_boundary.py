import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts.check_boundary import BoundaryError, load_json, validate_boundary, validate_spec


ROOT = Path(__file__).parents[1]
SPEC_PATH = ROOT / "specifications" / "worktree-capability-v1.json"
RECORD_PATH = ROOT / "specifications" / "fixtures" / "boundary-ar0004-v1.json"


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC_PATH)
        self.record = load_json(RECORD_PATH)

    def assert_rejected(self, record=None, revision=5):
        with self.assertRaises(BoundaryError):
            validate_boundary(record or self.record, self.spec, revision, "agent-workflow-runtime", "agent-workflow-runtime-0004")

    def test_valid_exact_binding_and_interruption(self):
        validate_spec(self.spec)
        result = validate_boundary(self.record, self.spec, 5, "agent-workflow-runtime", "agent-workflow-runtime-0004")
        self.assertEqual(result["final"], "interrupted")
        self.assertEqual(result["actions"], 5)
        self.assertEqual(result["project"], "agent-workflow-runtime")

    def test_evidence_binds_canonical_specification(self):
        canonical = json.dumps(self.spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(self.record["evidence"]["specification_digest"], "sha256:" + hashlib.sha256(canonical).hexdigest())
        self.assertEqual(self.record["evidence"]["task_revision"], 5)

    def test_stale_revision_and_cross_project_or_worktree_binding(self):
        self.assert_rejected(revision=4)
        stale = copy.deepcopy(self.record)
        stale["task"]["revision"] = 4
        self.assert_rejected(stale)
        other_project = copy.deepcopy(self.record)
        other_project["project"]["key"] = "other-project"
        self.assert_rejected(other_project)
        other_worktree = copy.deepcopy(self.record)
        other_worktree["worktree"]["isolation"] = "shared"
        self.assert_rejected(other_worktree)

    def test_malformed_unknown_and_replayed_actions_fail_closed(self):
        malformed = copy.deepcopy(self.record)
        del malformed["worktree"]["digest"]
        self.assert_rejected(malformed)
        unknown = copy.deepcopy(self.record)
        unknown["actions"][1]["unbounded"] = "output"
        self.assert_rejected(unknown)
        replay = copy.deepcopy(self.record)
        replay["actions"][4]["id"] = replay["actions"][3]["id"]
        self.assert_rejected(replay)

    def test_ungranted_tool_and_authority_mutation_are_rejected(self):
        tool = copy.deepcopy(self.record)
        tool["actions"][1]["tool"] = "network"
        self.assert_rejected(tool)
        authority = copy.deepcopy(self.record)
        authority["actions"][1]["operation"] = "authority_decision"
        self.assert_rejected(authority)
        publish = copy.deepcopy(self.record)
        publish["actions"][1]["operation"] = "publish"
        self.assert_rejected(publish)

    def test_invalid_transition_privacy_and_evidence_binding(self):
        transition = copy.deepcopy(self.record)
        transition["actions"][4]["operation"] = "close"
        self.assert_rejected(transition)
        state = copy.deepcopy(self.record)
        state["actions"][2]["state"] = "admitted"
        self.assert_rejected(state)
        private = copy.deepcopy(self.record)
        private["evidence"]["private_path"] = "not-public"
        self.assert_rejected(private)
        evidence = copy.deepcopy(self.record)
        evidence["evidence"]["task_revision"] = 4
        self.assert_rejected(evidence)


if __name__ == "__main__":
    unittest.main()

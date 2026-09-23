import copy
import unittest
from pathlib import Path

from scripts.awq_awg_bridge import BridgeError, canonical_bytes, project, sha256, validate
from scripts.check_awq_awg_bridge import load

ROOT = Path(__file__).parents[1]


class AwqAwgBridgeTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/awq-awg-bridge-v1.json")
        self.record = load(ROOT / "specifications/fixtures/awq-awg-bridge-ar0020-v1.json")
        self.evidence = load(ROOT / "specifications/fixtures/awq-awg-evidence-ar0020-v1.json")

    def test_positive_fixture_preserves_authority_boundaries(self):
        self.assertEqual(validate(self.record), {"evidence_references": 2, "oracle_batches": 1, "task_revision": 1, "session_id": "SES-AR0020-REFERENCE"})
        projection = project(self.record, sha256(canonical_bytes(self.spec)))
        self.assertEqual(projection["quality_status"], "not_decided")
        self.assertEqual(projection["oracle_status"], "not_decided")
        self.assertEqual(self.evidence["projection"], projection)

    def reject(self, record):
        with self.assertRaises(BridgeError):
            validate(record)

    def test_hostile_stale_replay_unknown_private_cross_and_authority_cases(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["evidence_references"][1]["evidence_digest"] = replay["evidence_references"][0]["evidence_digest"]; self.reject(replay)
        unknown = copy.deepcopy(self.record); unknown["oracle_batches"][0]["discussion"]["extra"] = "bad"; self.reject(unknown)
        private = copy.deepcopy(self.record); private["oracle_batches"][0]["discussion"]["context_digest"] = "prompt contents"; self.reject(private)
        cross = copy.deepcopy(self.record); cross["worktree"]["key"] = "other-worktree"; self.reject(cross)
        authority = copy.deepcopy(self.record); authority["oracle_batches"][0]["decision"]["authority"] = "runtime"; self.reject(authority)

    def test_decision_and_acceptance_injection_are_rejected(self):
        decision = copy.deepcopy(self.record); decision["oracle_batches"][0]["decision"]["status"] = "approved"; self.reject(decision)
        acceptance = copy.deepcopy(self.record); acceptance["evidence_references"][0]["submission_status"] = "accepted"; self.reject(acceptance)


if __name__ == "__main__":
    unittest.main()

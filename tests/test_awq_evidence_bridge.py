import copy
import unittest
from pathlib import Path

from scripts.awq_evidence_bridge import BridgeError, canonical_bytes, project_evidence, sha256, validate_bridge
from scripts.check_awq_evidence_bridge import load

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/awq-evidence-bridge-v1.json"
RECORD = ROOT / "specifications/fixtures/evidence-bridge-ar0009-v1.json"
EVIDENCE = ROOT / "specifications/fixtures/evidence-bridge-evidence-ar0009-v1.json"


class AwqEvidenceBridgeTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record, self.evidence = load(SPEC), load(RECORD), load(EVIDENCE)

    def test_fixture_binds_exact_revision_and_does_not_decide_quality(self):
        result = validate_bridge(self.record, 5)
        self.assertEqual(result["observations"], 3)
        projection = project_evidence(self.record, sha256(canonical_bytes(self.spec)))
        self.assertEqual(projection["quality_status"], "not_decided")
        self.assertNotIn("acceptance", projection)
        self.assertEqual(self.evidence["record_digest"], sha256(canonical_bytes(self.record)))
        self.assertEqual(self.evidence["projection"], projection)

    def reject(self, record=None, revision=5):
        with self.assertRaises(BridgeError):
            validate_bridge(record or self.record, revision)

    def test_hostile_stale_unknown_replay_privacy_and_cross_binding_cases(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 4; self.reject(stale)
        unknown = copy.deepcopy(self.record); unknown["observations"][0]["extra"] = "bad"; self.reject(unknown)
        replay = copy.deepcopy(self.record); replay["observations"][1]["evidence_digest"] = replay["observations"][0]["evidence_digest"]; self.reject(replay)
        privacy = copy.deepcopy(self.record); privacy["observations"][0]["raw_output"] = "secret"; self.reject(privacy)
        cross = copy.deepcopy(self.record); cross["worktree"]["key"] = "agent-workflow-runtime-0008"; self.reject(cross)

    def test_quality_decision_is_not_a_valid_observation_or_projection(self):
        decision = copy.deepcopy(self.record); decision["observations"][0]["result"] = "accepted"; self.reject(decision)
        projection = project_evidence(self.record, sha256(canonical_bytes(self.spec)))
        projection["quality_status"] = "accepted"
        self.assertNotEqual(projection, project_evidence(self.record, sha256(canonical_bytes(self.spec))))


if __name__ == "__main__":
    unittest.main()

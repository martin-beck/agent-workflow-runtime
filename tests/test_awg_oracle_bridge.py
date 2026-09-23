import copy
import unittest
from pathlib import Path

from scripts.awg_oracle_bridge import BridgeError, canonical_bytes, project_admission, sha256, validate_bridge
from scripts.check_awg_oracle_bridge import load

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/awg-oracle-bridge-v1.json"
RECORD = ROOT / "specifications/fixtures/oracle-bridge-ar0010-v1.json"


class AwgOracleBridgeTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(RECORD)

    def test_fixture_is_revision_bound_and_never_decides(self):
        result = validate_bridge(self.record, 3)
        self.assertEqual(result["observations"], 3)
        projection = project_admission(self.record, sha256(canonical_bytes(self.spec)))
        self.assertEqual(projection["admission_status"], "not_decided")
        self.assertEqual(projection["task"]["revision"], 3)
        self.assertNotIn("selected", projection)

    def reject(self, record=None, revision=3):
        with self.assertRaises(BridgeError):
            validate_bridge(record or self.record, revision)

    def test_hostile_stale_replay_unknown_private_and_cross_binding_cases(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["alternatives"][1]["evidence_digest"] = replay["alternatives"][0]["evidence_digest"]; self.reject(replay)
        unknown = copy.deepcopy(self.record); unknown["observations"][0]["extra"] = "bad"; self.reject(unknown)
        private = copy.deepcopy(self.record); private["observations"][0]["raw_output"] = "secret"; self.reject(private)
        cross = copy.deepcopy(self.record); cross["session"]["id"] = "SES-OTHER"; self.reject(cross)

    def test_decision_injection_is_rejected_and_projection_is_immutable_by_recomputation(self):
        decision = copy.deepcopy(self.record); decision["decision"] = "approved"; self.reject(decision)
        projection = project_admission(self.record, sha256(canonical_bytes(self.spec)))
        projection["admission_status"] = "accepted"
        self.assertNotEqual(projection, project_admission(self.record, sha256(canonical_bytes(self.spec))))


if __name__ == "__main__":
    unittest.main()

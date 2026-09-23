import copy
import unittest
from pathlib import Path

from scripts.ci_observation_adapter import ObservationError, canonical_bytes, project_evidence, sha256, validate_record
from scripts.check_ci_observation_adapter import load

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/ci-observation-adapter-v1.json"
RECORD = ROOT / "specifications/fixtures/ci-observation-ar0013-v1.json"
EVIDENCE = ROOT / "specifications/fixtures/ci-observation-evidence-ar0013-v1.json"


class CiObservationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record, self.evidence = load(SPEC), load(RECORD), load(EVIDENCE)

    def reject(self, record=None, revision=1):
        with self.assertRaises(ObservationError):
            validate_record(record or self.record, revision)

    def test_positive_fixture_is_revision_bound_and_separates_local_and_remote(self):
        result = validate_record(self.record, 1)
        self.assertEqual(result["local"], "qualified")
        self.assertEqual(result["remote"], "unverified")
        self.assertEqual(self.record["disposition"], "local_qualified_remote_unverified")
        self.assertEqual(self.evidence["record_digest"], sha256(canonical_bytes(self.record)))
        self.assertEqual(self.evidence["projection"], project_evidence(self.record, self.evidence["specification_digest"]))

    def test_hostile_stale_replay_unknown_private_cases(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 0; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["evidence"][1] = copy.deepcopy(replay["evidence"][0]); self.reject(replay)
        unknown = copy.deepcopy(self.record); unknown["request"]["extra"] = "bad"; self.reject(unknown)
        private = copy.deepcopy(self.record); private["request"]["input_digest"] = "password=leaked"; self.reject(private)

    def test_hostile_wrong_correlation_and_unverified_success_cases(self):
        wrong_request = copy.deepcopy(self.record); wrong_request["remote_observation"]["request_id"] = "RQ-AR0013-02"; self.reject(wrong_request)
        wrong_target = copy.deepcopy(self.record); wrong_target["correlation"]["target_digest"] = "sha256:" + "1" * 64; self.reject(wrong_target)
        verified = copy.deepcopy(self.record); verified["remote_observation"]["verification"] = "verified"; self.reject(verified)
        promoted = copy.deepcopy(self.record); promoted["disposition"] = "remote_verified_success"; self.reject(promoted)


if __name__ == "__main__":
    unittest.main()

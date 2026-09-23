import copy
import unittest
from pathlib import Path

from scripts.check_fresh_clone_release import CheckError, load, validate_record, validate_spec
from scripts.fresh_clone_release import ReleaseLockError, evaluate_lock

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/fresh-clone-release-lock-v1.json"
FIXTURE = ROOT / "specifications/fixtures/fresh-clone-release-ar0027-v1.json"


class FreshCloneReleaseTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(FIXTURE)

    def reject(self, record=None, revision=3):
        with self.assertRaises(CheckError):
            validate_record(record or self.record, self.spec, revision)

    def test_positive_lock_is_reproducible_and_rollback_ready(self):
        validate_spec(self.spec)
        result = validate_record(self.record, self.spec)
        self.assertEqual(result["status"], "rollback_ready")
        self.assertEqual(result["publication"], "not_performed")
        self.assertEqual(result["remote_verification"], "unverified")

    def test_stale_replay_malformed_and_privacy_fail_closed(self):
        self.reject(revision=2)
        replay = copy.deepcopy(self.record)
        replay["compatibility"]["contracts"][1] = replay["compatibility"]["contracts"][0]
        self.reject(replay)
        private = copy.deepcopy(self.record)
        private["release"]["credential"] = "not allowed"
        self.reject(private)
        malformed = copy.deepcopy(self.record)
        malformed["installation"]["dependencies"][0]["version"] = "latest"
        self.reject(malformed)

    def test_interruption_unauthorized_release_and_wrong_recovery_fail(self):
        interrupted = copy.deepcopy(self.record)
        interrupted["release"]["status"] = "interrupted"
        self.reject(interrupted)
        unauthorized = copy.deepcopy(self.record)
        unauthorized["release"]["publication"] = "performed"
        self.reject(unauthorized)
        wrong_target = copy.deepcopy(self.record)
        wrong_target["rollback"]["target_digest"] = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
        self.reject(wrong_target)

    def test_model_rejects_network_and_missing_contract(self):
        network = copy.deepcopy(self.record)
        network["installation"]["network"] = "required"
        with self.assertRaises(ReleaseLockError):
            evaluate_lock(network)
        missing = copy.deepcopy(self.record)
        missing["compatibility"]["contracts"] = missing["compatibility"]["contracts"][:2]
        with self.assertRaises(ReleaseLockError):
            evaluate_lock(missing)


if __name__ == "__main__":
    unittest.main()

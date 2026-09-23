import copy
import unittest
from pathlib import Path

from scripts.check_umbrella_maintenance import CheckError, load, validate_record, validate_spec
from scripts.umbrella_maintenance import UmbrellaError, evaluate

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/umbrella-maintenance-v1.json"
FIXTURE = ROOT / "specifications/fixtures/umbrella-maintenance-ar0028-v1.json"


class UmbrellaMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(FIXTURE)

    def reject(self, record=None, revision=3):
        with self.assertRaises(CheckError):
            validate_record(record or self.record, self.spec, revision)

    def test_positive_registration_and_ordered_maintenance(self):
        validate_spec(self.spec)
        result = validate_record(self.record, self.spec)
        self.assertEqual(result["status"], "maintenance_ready")
        self.assertEqual(result["phases"], 7)
        self.assertEqual(result["release"], "not_performed")

    def test_stale_malformed_replay_and_privacy_fail_closed(self):
        self.reject(revision=2)
        replay = copy.deepcopy(self.record)
        replay["transitions"][1] = copy.deepcopy(replay["transitions"][0])
        self.reject(replay)
        malformed = copy.deepcopy(self.record)
        malformed["transitions"][2].pop("output_digest")
        self.reject(malformed)
        private = copy.deepcopy(self.record)
        private["maintenance"]["private_path"] = "/home/agent/private"
        self.reject(private)

    def test_interruption_unauthorized_cross_binding_and_replay_fail(self):
        interrupted = copy.deepcopy(self.record)
        interrupted["maintenance"]["status"] = "interrupted"
        self.reject(interrupted)
        unauthorized = copy.deepcopy(self.record)
        unauthorized["transitions"][4]["authority"] = "coordinator"
        self.reject(unauthorized)
        crossed = copy.deepcopy(self.record)
        crossed["worktree"]["key"] = "agent-workflow-runtime-0027"
        self.reject(crossed)
        duplicate_id = copy.deepcopy(self.record)
        duplicate_id["transitions"][6]["id"] = "TR-6"
        self.reject(duplicate_id)

    def test_model_rejects_release_claim_and_wrong_phase(self):
        release = copy.deepcopy(self.record)
        release["maintenance"]["release"] = "performed"
        with self.assertRaises(UmbrellaError):
            evaluate(release)
        wrong_phase = copy.deepcopy(self.record)
        wrong_phase["transitions"][0]["phase"] = "runtime"
        with self.assertRaises(UmbrellaError):
            evaluate(wrong_phase)


if __name__ == "__main__":
    unittest.main()

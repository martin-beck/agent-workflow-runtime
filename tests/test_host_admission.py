import copy
import unittest
from pathlib import Path

from scripts.check_host_admission import CHECKER, check, load
from scripts.host_admission import HostAdmissionError

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/host-admission-v1.json"
FIXTURE = ROOT / "specifications/fixtures/host-admission-ar0048-v1.json"


class HostAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(SPEC)
        self.record = load(FIXTURE)

    def test_offline_least_privilege_cancel_cleanup_and_recovery(self):
        result = check(self.spec, self.record, 5)
        self.assertEqual(result["checker"], CHECKER)
        self.assertEqual(result["final_state"], "running")
        self.assertEqual(result["task_revision"], 5)

    def assert_rejected(self, record):
        with self.assertRaises(HostAdmissionError):
            check(self.spec, record, 5)

    def test_unsupported_host_feature_fails_closed(self):
        record = copy.deepcopy(self.record)
        record["host_capabilities"]["network_isolation"] = False
        self.assert_rejected(record)

    def test_shell_and_network_policy_fail_closed(self):
        record = copy.deepcopy(self.record)
        record["actions"][0]["argv"] = ["python3", "-c", "x; y"]
        record["actions"][0]["action_digest"] = "sha256:" + "0" * 64
        self.assert_rejected(record)
        record = copy.deepcopy(self.record)
        record["actions"][0]["network"] = "allow"
        self.assert_rejected(record)

    def test_limit_exhaustion_and_incomplete_cleanup_fail_closed(self):
        record = copy.deepcopy(self.record)
        record["actions"][0]["observation"]["memory_mb"] = record["budgets"]["memory_mb"] + 1
        self.assert_rejected(record)
        record = copy.deepcopy(self.record)
        record["actions"][2]["observation"]["tree_complete"] = False
        self.assert_rejected(record)

    def test_old_worker_cannot_resume(self):
        record = copy.deepcopy(self.record)
        record["actions"][-1]["worker_id"] = "WRK-OLD"
        self.assert_rejected(record)


if __name__ == "__main__":
    unittest.main()

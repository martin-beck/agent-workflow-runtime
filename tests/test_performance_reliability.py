import copy
import unittest
from pathlib import Path

from scripts.check_performance_reliability import QualificationCheckError, canonical, load, sha, validate_record, validate_spec
from scripts.performance_reliability import QualificationError, evaluate_observation

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/performance-reliability-qualification-v1.json"
RECORD = ROOT / "specifications/fixtures/performance-reliability-ar0026-v1.json"


class PerformanceReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(RECORD)

    def reject(self, record=None, revision=1):
        with self.assertRaises(QualificationCheckError):
            validate_record(record or self.record, self.spec, revision)

    def test_positive_fixture_is_bounded_and_non_live(self):
        validate_spec(self.spec)
        result = validate_record(self.record, self.spec, 1)
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(result["source"], "supplied_qualification")
        self.assertEqual(result["live_measurement"], "not_performed")
        self.assertEqual(set(item["category"] for item in self.record["observations"]), {"latency", "throughput", "recovery", "resource_use", "failure_behavior"})

    def test_stale_replay_budget_measurement_and_privacy_fail_closed(self):
        self.reject(revision=2)
        replay = copy.deepcopy(self.record); replay["observations"][1] = copy.deepcopy(replay["observations"][0]); self.reject(replay)
        budget = copy.deepcopy(self.record); budget["observations"][0]["value"] = 1001; self.reject(budget)
        live = copy.deepcopy(self.record); live["qualification"]["live_measurement"] = "success"; self.reject(live)
        private = copy.deepcopy(self.record); private["observations"][0]["metric"] = "private_path"; self.reject(private)

    def test_spec_and_result_tampering_and_invalid_observation_fail(self):
        changed = copy.deepcopy(self.record); changed["result"]["status"] = "live_success"; self.reject(changed)
        unknown = copy.deepcopy(self.record); unknown["observations"][0]["extra"] = 1; self.reject(unknown)
        invalid = copy.deepcopy(self.record["observations"][0]); invalid["specification"]["operator"] = "equal" 
        with self.assertRaises(QualificationError):
            evaluate_observation(invalid)
        hostile = copy.deepcopy(self.record); hostile["observations"][2]["value"] = 16; self.reject(hostile)


if __name__ == "__main__":
    unittest.main()

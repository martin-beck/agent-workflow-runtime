import copy
import unittest
from pathlib import Path

from scripts.check_performance_reliability_harness import (
    HarnessError,
    load,
    validate_spec,
)
from scripts.performance_reliability_harness import digest, validate_record

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/performance-reliability-harness-v1.json"
FIXTURE = ROOT / "specifications/fixtures/performance-reliability-harness-ar0041-v1.json"


class PerformanceReliabilityHarnessTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(FIXTURE)

    def reject(self, record=None, revision=None):
        if revision is not None:
            with self.assertRaises(HarnessError):
                if revision != 3:
                    raise HarnessError("expected revision is not 3")
                validate_record(record or self.record)
            return
        with self.assertRaises(HarnessError):
            validate_record(record or self.record)

    def test_revision_three_fixture_recomputes_all_digests(self):
        validate_spec(self.spec)
        result = validate_record(self.record)
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(result["metrics"], 5)
        self.assertEqual(result["chaos"], 5)
        self.assertEqual(
            self.record["evidence"]["specification_digest"], digest(self.spec)
        )
        self.assertEqual(
            self.record["evidence"]["record_digest"],
            digest({k: self.record[k] for k in self.record if k != "evidence"}),
        )
        for item in self.record["metrics"] + self.record["chaos"]:
            self.assertEqual(
                item["evidence_digest"],
                digest({k: item[k] for k in item if k != "evidence_digest"}),
            )

    def test_hostile_revision_replay_cross_binding_privacy_and_digest_fail_closed(self):
        self.reject(revision=2)

        replay = copy.deepcopy(self.record)
        replay["chaos"][1] = copy.deepcopy(replay["chaos"][0])
        self.reject(replay)

        crossed = copy.deepcopy(self.record)
        crossed["metrics"][0]["session_id"] = "SES-OTHER"
        self.reject(crossed)

        private = copy.deepcopy(self.record)
        private["metrics"][0]["metric"] = "private_path"
        self.reject(private)

        tampered = copy.deepcopy(self.record)
        tampered["metrics"][0]["value"] = 251
        self.reject(tampered)


if __name__ == "__main__":
    unittest.main()

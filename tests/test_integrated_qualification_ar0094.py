import copy
import json
import unittest
from pathlib import Path

from scripts.integrated_qualification import (
    IntegratedQualificationError,
    simulate,
    validate,
)

FIXTURE = (
    Path(__file__).parents[1]
    / "specifications/fixtures/integrated-qualification-ar0094-v1.json"
)


class IntegratedQualificationAR0094Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text())

    def test_virtual_qualification_covers_hundreds_and_replays(self):
        result = validate(self.record)
        self.assertEqual(result["jobs"], 256)
        self.assertTrue(result["replay_equal"])

    def test_counterexample_or_replay_mismatch_fails_closed(self):
        record = copy.deepcopy(self.record)
        record["replay"]["counterexample"] = {"step": 4}
        with self.assertRaisesRegex(
            IntegratedQualificationError, "replay_equality_failed"
        ):
            validate(record)

    def test_undersized_run_is_not_qualification(self):
        with self.assertRaisesRegex(
            IntegratedQualificationError, "unsupported_simulation_size"
        ):
            simulate(17, 32)


if __name__ == "__main__":
    unittest.main()

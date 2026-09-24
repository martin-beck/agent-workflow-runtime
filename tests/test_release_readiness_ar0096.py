import copy
import json
import unittest
from pathlib import Path

from scripts.release_readiness_gate import ReleaseReadinessError, validate

FIXTURE = (
    Path(__file__).parents[1]
    / "specifications/fixtures/release-readiness-ar0096-v1.json"
)


class ReleaseReadinessAR0096Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text())

    def test_readiness_fixture_is_qualified_with_rollback_prepared(self):
        result = validate(self.record)
        self.assertEqual(result["sections"], 12)
        self.assertEqual(result["rollback"], "prepared")

    def test_missing_section_fails_closed(self):
        record = copy.deepcopy(self.record)
        record["sections"].pop()
        with self.assertRaisesRegex(
            ReleaseReadinessError, "incomplete_readiness_sections"
        ):
            validate(record)

    def test_live_release_claim_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["release"]["live_release"] = "performed"
        with self.assertRaisesRegex(
            ReleaseReadinessError, "release_ownership_or_boundary_failure"
        ):
            validate(record)


if __name__ == "__main__":
    unittest.main()

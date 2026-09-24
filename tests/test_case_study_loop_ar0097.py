import copy
import json
import unittest
from pathlib import Path

from scripts.case_study_loop import CaseStudyError, validate

FIXTURE = (
    Path(__file__).parents[1] / "specifications/fixtures/case-study-loop-ar0097-v1.json"
)


class CaseStudyLoopAR0097Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text())

    def test_case_studies_are_cross_project_and_proposal_only(self):
        result = validate(self.record)
        self.assertEqual(result["cycles"], 2)
        self.assertTrue(result["proposal_only"])

    def test_missing_evidence_fails_closed(self):
        record = copy.deepcopy(self.record)
        record["cycles"][0]["evidence_digest"] = (
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        with self.assertRaisesRegex(CaseStudyError, "cycle_digest_mismatch"):
            validate(record)

    def test_finding_cannot_approve_or_mutate_policy(self):
        record = copy.deepcopy(self.record)
        record["findings"] = [
            {
                "kind": "improvement_proposal",
                "code": "approve_release",
                "count": 1,
                "proposal_only": False,
                "evidence_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        ]
        with self.assertRaisesRegex(CaseStudyError, "invalid_finding_or_approval"):
            validate(record)


if __name__ == "__main__":
    unittest.main()

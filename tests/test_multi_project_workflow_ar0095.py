import copy
import json
import unittest
from pathlib import Path

from scripts.multi_project_workflow import MultiProjectWorkflowError, validate

FIXTURE = (
    Path(__file__).parents[1]
    / "specifications/fixtures/multi-project-workflow-ar0095-v1.json"
)


class MultiProjectWorkflowAR0095Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text())

    def test_full_workflow_fixture_reconciles(self):
        result = validate(self.record)
        self.assertEqual(result["stages"], 10)
        self.assertTrue(result["reconciled"])

    def test_skipping_quality_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["operations"] = [
            operation
            for operation in record["operations"]
            if operation["stage"] != "quality"
        ]
        with self.assertRaisesRegex(MultiProjectWorkflowError, "incomplete_workflow"):
            validate(record)

    def test_parallel_worker_requires_resume_evidence(self):
        record = copy.deepcopy(self.record)
        next(
            operation
            for operation in record["operations"]
            if operation["stage"] == "specialist_b"
        )["resumed"] = False
        with self.assertRaisesRegex(
            MultiProjectWorkflowError, "safe_resume_not_proven"
        ):
            validate(record)


if __name__ == "__main__":
    unittest.main()

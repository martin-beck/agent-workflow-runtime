import copy
import unittest
from pathlib import Path

from scripts.check_full_workflow_orchestrator import load
from scripts.full_workflow_orchestrator import OrchestrationError, validate_record

ROOT = Path(__file__).parents[1]


class FullWorkflowOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.record = load(ROOT / "specifications/fixtures/full-workflow-orchestrator-ar0043-v1.json")

    def test_offline_terminal_success_is_complete_and_unverified(self):
        result = validate_record(self.record, 3)
        self.assertEqual(result["operations"], 9)
        self.assertFalse(result["execute"])
        self.assertEqual(result["remote_verification"], "unverified")

    def test_tampered_dependency_and_terminal_state_fail_closed(self):
        for mutation in (
            lambda r: r["operations"][8].update(depends_on=[]),
            lambda r: r["operations"][4].update(status="blocked"),
            lambda r: r["terminal"].update(status="success", execute=True),
        ):
            changed = copy.deepcopy(self.record)
            mutation(changed)
            with self.assertRaises(OrchestrationError):
                validate_record(changed, 3)


if __name__ == "__main__":
    unittest.main()

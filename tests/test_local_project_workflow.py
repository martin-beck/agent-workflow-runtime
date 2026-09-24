import copy
import json
import unittest
from pathlib import Path

from awr_cli.cli import validate_manifest
from scripts.local_project_workflow import SPECIFICATION, WorkflowError, run, validate


ROOT = Path(__file__).parents[1]


class LocalProjectWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / "project-manifest.yaml").read_bytes()
        _, self.revision = validate_manifest(self.raw)
        self.record = run(self.raw, self.revision)

    def reject(self, record, expected_revision=None):
        with self.assertRaises(WorkflowError):
            validate(record, expected_revision)

    def test_bootstrap_composed_workflow_is_deterministic_and_reconciled(self):
        self.assertEqual(self.record, run(self.raw, self.revision))
        self.assertEqual(validate(self.record, self.revision)["status"], "reconciled")
        self.assertEqual(len(self.record["events"]), 8)

    def test_skipping_each_authority_gate_fails_closed(self):
        for authority in ("awq", "awg", "ui"):
            record = copy.deepcopy(self.record)
            record["events"] = [event for event in record["events"] if event["authority"] != authority]
            self.reject(record)

    def test_changed_specification_tests_and_unresolved_repair_escalation_rejected(self):
        altered_spec = copy.deepcopy(self.record)
        altered_spec["specification_digest"] = "sha256:" + "0" * 64
        self.reject(altered_spec)
        altered_test_contract = copy.deepcopy(self.record)
        altered_test_contract["test_contract_digest"] = "sha256:" + "0" * 64
        self.reject(altered_test_contract)
        altered_tests = copy.deepcopy(self.record)
        altered_tests["events"][3]["kind"] = "tests_skipped"
        self.reject(altered_tests)
        unresolved = copy.deepcopy(self.record)
        unresolved["events"][5]["kind"] = "repair_unresolved"
        self.reject(unresolved)

    def test_stale_revision_and_replay_rejected(self):
        self.reject(copy.deepcopy(self.record), "sha256:" + "0" * 64)
        stale = copy.deepcopy(self.record)
        stale["events"][0]["project_revision"] = "sha256:" + "0" * 64
        self.reject(stale)
        replay = copy.deepcopy(self.record)
        replay["events"][1]["event_id"] = replay["events"][0]["event_id"]
        self.reject(replay)

    def test_terminal_reconciliation_cannot_be_claimed_by_runtime(self):
        record = copy.deepcopy(self.record)
        record["terminal"]["coordinator"] = "runtime_approved"
        self.reject(record)


if __name__ == "__main__":
    unittest.main()


import copy
import unittest
from pathlib import Path

from scripts.check_resource_boundary import ResourceCheckError, load_json, validate_spec, validate_trace
from scripts.resource_boundary import ResourceBoundaryError, ResourceBudget, evaluate

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/resource-boundary-v1.json"
TRACE = ROOT / "specifications/fixtures/resource-trace-ar0006-v1.json"


class ResourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC)
        self.trace = load_json(TRACE)

    def reject(self, trace=None, revision=5):
        with self.assertRaises(ResourceCheckError):
            validate_trace(trace or self.trace, self.spec, revision)

    def test_valid_trace_and_deterministic_result(self):
        validate_spec(self.spec)
        result = validate_trace(self.trace, self.spec, 5)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(evaluate(self.trace["budget"], self.trace["observation"]), self.trace["result"])

    def test_each_budget_and_termination_boundary_fails_closed(self):
        for field in ("cpu_ms", "memory_bytes", "disk_bytes", "network_bytes", "process_count", "process_depth"):
            observation = copy.deepcopy(self.trace["observation"])
            observation[field] = self.trace["budget"][field] + 1
            result = evaluate(self.trace["budget"], observation)
            self.assertFalse(result["accepted"], field)
            self.assertIn(field, result["violations"])
        timeout = copy.deepcopy(self.trace["observation"])
        timeout["elapsed_ms"] = self.trace["budget"]["timeout_ms"] + 1
        self.assertIn("timeout_ms", evaluate(self.trace["budget"], timeout)["violations"])
        incomplete = copy.deepcopy(self.trace["observation"])
        incomplete["process_tree_complete"] = False
        self.assertIn("process_tree_complete", evaluate(self.trace["budget"], incomplete)["violations"])
        cancelled = copy.deepcopy(self.trace["observation"])
        cancelled["cancel_requested"] = True
        self.assertIn("cancellation", evaluate(self.trace["budget"], cancelled)["violations"])
        cancelled["cancel_acknowledged"] = True
        self.assertNotIn("cancellation", evaluate(self.trace["budget"], cancelled)["violations"])
        orphan_ack = copy.deepcopy(self.trace["observation"])
        orphan_ack["cancel_acknowledged"] = True
        self.assertIn("cancellation_state", evaluate(self.trace["budget"], orphan_ack)["violations"])

    def test_stale_revision_unknown_fields_privacy_and_result_tampering_reject(self):
        self.reject(revision=4)
        for mutation in (
            lambda value: value["observation"].pop("cpu_ms"),
            lambda value: value["observation"].update({"host_identifier": "node-1"}),
            lambda value: value["evidence"].update({"token": "forbidden"}),
            lambda value: value["result"].update({"accepted": False, "disposition": "rejected", "violations": ["cpu_ms"]}),
        ):
            changed = copy.deepcopy(self.trace)
            mutation(changed)
            self.reject(changed)

    def test_invalid_types_and_zero_budgets_reject(self):
        with self.assertRaises(ResourceBoundaryError):
            ResourceBudget.from_mapping({name: 0 for name in ResourceBudget.__dataclass_fields__})
        invalid = copy.deepcopy(self.trace["observation"])
        invalid["cpu_ms"] = True
        with self.assertRaises(ResourceBoundaryError):
            evaluate(self.trace["budget"], invalid)
        invalid = copy.deepcopy(self.trace["observation"])
        invalid["cpu_ms"] = 1 << 63
        with self.assertRaises(ResourceBoundaryError):
            evaluate(self.trace["budget"], invalid)
        invalid = copy.deepcopy(self.trace["observation"])
        invalid["cancel_requested"] = 1
        with self.assertRaises(ResourceBoundaryError):
            evaluate(self.trace["budget"], invalid)


if __name__ == "__main__":
    unittest.main()

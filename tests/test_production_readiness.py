import copy
import unittest
from pathlib import Path

from scripts.check_production_readiness import load, validate_spec
from scripts.production_readiness import ReadinessError, validate_record

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/production-readiness-harness-v1.json"
FIXTURE = ROOT / "specifications/fixtures/production-readiness-ar0045-v1.json"


class ProductionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(FIXTURE)

    def test_versioned_revision_five_harness_is_offline_qualified(self):
        validate_spec(self.spec)
        result = validate_record(self.record, 5)
        self.assertEqual(result["task_revision"], 5)
        self.assertEqual(result["sections"], ["readiness", "upgrade", "rollback", "incident", "maintenance"])
        self.assertFalse(result["execute"])
        self.assertEqual(result["release"], "not_performed")
        self.assertEqual(result["publication"], "not_performed")
        self.assertEqual(result["provider_execution"], "unverified")
        self.assertEqual(result["remote_verification"], "unverified")

    def test_hostile_revision_and_execution_claims_fail_closed(self):
        mutations = (
            (lambda r: r["task"].update(revision=4)),
            (lambda r: r["readiness"].update(task_revision=4)),
            (lambda r: r["upgrade"]["checks"].append("network_call")),
            (lambda r: r["rollback"].update(status="executed")),
            (lambda r: r["incident"]["checks"].append("secret_token")),
            (lambda r: r["maintenance"]["checks"].clear()),
            (lambda r: r["terminal"].update(execute=True)),
            (lambda r: r["terminal"].update(provider_execution="performed")),
            (lambda r: r["evidence"].update(task_revision=4)),
        )
        for mutation in mutations:
            changed = copy.deepcopy(self.record)
            mutation(changed)
            with self.assertRaises(ReadinessError):
                validate_record(changed, 5)

    def test_checker_invocation_revision_is_exactly_five(self):
        with self.assertRaises(ReadinessError):
            validate_record(self.record, 4)


if __name__ == "__main__":
    unittest.main()

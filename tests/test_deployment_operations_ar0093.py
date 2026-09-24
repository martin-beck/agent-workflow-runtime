import copy
import json
import unittest
from pathlib import Path

from scripts.deployment_operations import DeploymentOperationsError, validate

FIXTURE = (
    Path(__file__).parents[1]
    / "specifications/fixtures/deployment-operations-ar0093-v1.json"
)


class DeploymentOperationsAR0093Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text())

    def test_fixture_is_qualified_without_execution(self):
        result = validate(self.record)
        self.assertEqual(result["status"], "qualified")
        self.assertFalse(result["execute"])

    def test_rollout_execution_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["rollout"]["execute"] = True
        with self.assertRaisesRegex(
            DeploymentOperationsError, "rollout_exceeds_offline_boundary"
        ):
            validate(record)

    def test_rollback_must_target_exact_prior_artifact(self):
        record = copy.deepcopy(self.record)
        record["rollback"]["target_digest"] = (
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        with self.assertRaisesRegex(DeploymentOperationsError, "rollback_not_exact"):
            validate(record)

    def test_stale_health_fails_closed(self):
        record = copy.deepcopy(self.record)
        record["health"]["stale"] = True
        with self.assertRaisesRegex(
            DeploymentOperationsError, "health_gate_not_passed"
        ):
            validate(record)


if __name__ == "__main__":
    unittest.main()

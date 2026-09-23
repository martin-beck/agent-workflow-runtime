import copy
import unittest
from pathlib import Path

from scripts.check_production_deployment_release import load, validate_spec
from scripts.production_deployment_release import DeploymentReleaseError, validate

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/production-deployment-release-v1.json"
FIXTURE = ROOT / "specifications/fixtures/production-deployment-release-ar0058-v1.json"


class ProductionDeploymentReleaseTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record = load(SPEC), load(FIXTURE)

    def reject(self, record=None):
        with self.assertRaises(DeploymentReleaseError):
            validate(record or self.record)

    def test_positive_offline_release_boundary(self):
        validate_spec(self.spec)
        result = validate(self.record)
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(result["compatibility"], "compatible")
        self.assertEqual(result["rollback"], "ready")
        self.assertFalse(result["execute"])
        self.assertEqual(result["publication"], "not_performed")
        self.assertEqual(result["remote_verification"], "unverified")

    def test_hostile_stale_execution_and_crossed_bindings_fail_closed(self):
        mutations = (
            lambda r: r["task"].update(revision=4),
            lambda r: r["deployment"].update(execute=True),
            lambda r: r["deployment"].update(network="required"),
            lambda r: r["compatibility"]["contracts"][1].update(id=r["compatibility"]["contracts"][0]["id"]),
            lambda r: r["upgrade"].update(downgrade_guard="latest"),
            lambda r: r["rollback"].update(target_digest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            lambda r: r["release"].update(publication="performed"),
            lambda r: r["release"].update(execute=True),
            lambda r: r["release"]["steps"].reverse(),
            lambda r: r["packaging"].update(secret="forbidden"),
        )
        for mutation in mutations:
            changed = copy.deepcopy(self.record)
            mutation(changed)
            self.reject(changed)

    def test_revision_and_provenance_fail_closed(self):
        with self.assertRaises(DeploymentReleaseError):
            validate(self.record, 4)
        wrong = copy.deepcopy(self.record)
        wrong["packaging"]["artifact"]["artifact_digest"] = wrong["packaging"]["artifact"]["source_digest"]
        self.reject(wrong)
        wrong = copy.deepcopy(self.record)
        wrong["upgrade"]["from_version"] = wrong["upgrade"]["to_version"]
        self.reject(wrong)


if __name__ == "__main__":
    unittest.main()

import copy
import json
import unittest
from pathlib import Path

from scripts.operational_observability import OperationalObservabilityError, validate

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "specifications/fixtures/operational-observability-ar0091-v1.json"


class OperationalObservabilityAR0091Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())

    def test_fixture_is_privacy_safe_and_non_authoritative(self):
        result = validate(self.fixture)
        self.assertEqual(result["task_revision"], 3)
        self.assertEqual(result["agents"], 2)
        self.assertEqual(result["observations"], 7)
        self.assertEqual(result["authority"], "observed_not_authoritative")

    def test_private_observation_is_rejected(self):
        record = copy.deepcopy(self.fixture)
        record["observations"][0]["attributes"] = {"prompt": "must not be exported"}
        with self.assertRaisesRegex(
            OperationalObservabilityError, "observation_digest_mismatch"
        ):
            validate(record)

    def test_stale_health_is_rejected(self):
        record = copy.deepcopy(self.fixture)
        record["health"]["stale"] = True
        with self.assertRaisesRegex(
            OperationalObservabilityError, "stale_or_claimed_health"
        ):
            validate(record)

    def test_non_authoritative_dashboard_cannot_be_changed_to_approval(self):
        record = copy.deepcopy(self.fixture)
        record["dashboards"]["queue"]["observed_not_authoritative"] = False
        with self.assertRaisesRegex(OperationalObservabilityError, "invalid_dashboard"):
            validate(record)

    def test_chain_and_cardinality_are_enforced(self):
        record = copy.deepcopy(self.fixture)
        record["observations"][1]["previous_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            OperationalObservabilityError, "observation_chain_mismatch"
        ):
            validate(record)


if __name__ == "__main__":
    unittest.main()

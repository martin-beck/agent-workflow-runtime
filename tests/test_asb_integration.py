import copy
import json
import unittest
from pathlib import Path

from scripts.asb_integration import IntegrationError, digest, validate


ROOT = Path(__file__).parents[1]


class AsbIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / "specifications/fixtures/asb-integration-ar0055-v1.json").read_text(encoding="utf-8"))

    def reject(self, mutation):
        changed = copy.deepcopy(self.record)
        mutation(changed)
        with self.assertRaises(IntegrationError):
            validate(changed, 5)

    def test_complete_offline_user_workflow_and_boundaries(self):
        result = validate(self.record, 5)
        self.assertEqual(result["agents"], ["AG-CODEX", "AG-OPENDESK"])
        self.assertEqual(result["benchmark_run"], "not_performed")
        self.assertEqual(result["comparison"], "structurally_comparable")
        self.assertFalse(result["execute"])

    def test_stale_crossed_replayed_and_private_inputs_fail_closed(self):
        self.reject(lambda r: r["task"].update(revision=4))
        self.reject(lambda r: r["trace"][2].update(binding_digest="sha256:" + "3" * 64))
        self.reject(lambda r: r["trace"][1].update(operation_id=r["trace"][0]["operation_id"]))
        self.reject(lambda r: r["trace"][6]["details"].update(response_payload="raw"))

    def test_configuration_cancellation_and_comparison_are_fenced(self):
        self.reject(lambda r: r["trace"][5]["details"].update(configuration_digest="sha256:" + "4" * 64))
        self.reject(lambda r: r["trace"][7]["cancellation"].update(acknowledged=False))
        self.reject(lambda r: r["trace"][8]["details"].update(agent_ids=["AG-CODEX"]))

    def test_digest_and_live_claim_tampering_fail_closed(self):
        self.reject(lambda r: r["terminal"].update(provider="supported"))
        self.reject(lambda r: r["evidence"].update(record_digest=digest(b"tampered")))


if __name__ == "__main__":
    unittest.main()

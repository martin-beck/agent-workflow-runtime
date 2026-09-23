import copy
import json
import unittest
from pathlib import Path

from scripts.provider_execution_security import ProviderSecurityError, canonical_bytes, sha256, validate


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/provider-execution-security-v1.json"
FIXTURE = ROOT / "specifications/fixtures/provider-execution-security-ar0049-v1.json"


class ProviderExecutionSecurityTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def reject(self, record=None):
        with self.assertRaises(ProviderSecurityError):
            validate(record or self.record, 5)

    def test_fixture_is_revision_bound_and_deterministic(self):
        result = validate(self.record, 5)
        self.assertEqual(result["contract"], "awr-provider-execution-security@1.0.0")
        self.assertEqual(result["operations"], 10)
        self.assertEqual(result["unknown_outcomes"], 1)

    def test_secret_values_destination_and_transport_fail_closed(self):
        for mutate in (
            lambda r: r["references"][0].update(value="do-not-accept"),
            lambda r: r["destinations"][0].update(url="http://provider.example:80"),
            lambda r: r["operations"][0]["response"]["frames"][0].update(bytes=2049),
            lambda r: r["operations"][0]["cancellation"].update(requested=True, acknowledged=False),
        ):
            record = copy.deepcopy(self.record); mutate(record); self.reject(record)

    def test_stale_duplicate_retry_and_unknown_outcome_are_not_success(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 4; self.reject(stale)
        duplicate = copy.deepcopy(self.record); duplicate["operations"].append(copy.deepcopy(duplicate["operations"][0])); self.reject(duplicate)
        retry = copy.deepcopy(self.record); retry["operations"][1]["attempt"] = 1; self.reject(retry)
        self.assertEqual(self.record["operations"][-1]["response"]["outcome"], "unknown")
        self.assertEqual(self.record["operations"][-1]["response"]["status"], "unknown")

    def test_spec_is_normative_and_offline(self):
        spec = json.loads(SPEC.read_text(encoding="utf-8"))
        self.assertTrue(spec["normative"])
        self.assertEqual(spec["offline_boundary"]["provider"], "not_performed")
        self.assertEqual(sha256(canonical_bytes(spec)).startswith("sha256:"), True)


if __name__ == "__main__":
    unittest.main()

import copy
import json
import unittest
from pathlib import Path

from scripts.production_integration_baseline import IntegrationError, canonical_bytes, digest, validate, validate_spec


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/production-integration-baseline-v1.json"
FIXTURE = ROOT / "specifications/fixtures/production-integration-baseline-ar0080-v1.json"
UNSUPPORTED = ROOT / "specifications/fixtures/production-integration-unsupported-ar0080-v1.json"


class ProductionIntegrationBaselineTests(unittest.TestCase):
    def setUp(self):
        self.spec = json.loads(SPEC.read_text(encoding="utf-8"))
        self.record = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.unsupported = json.loads(UNSUPPORTED.read_text(encoding="utf-8"))

    @staticmethod
    def bind(record):
        record["evidence"]["record_digest"] = digest(canonical_bytes({key: record[key] for key in record if key != "evidence"}))
        return record

    def reject(self, record=None, spec=None):
        with self.assertRaises(IntegrationError):
            validate(record or self.record, spec or self.spec, 1)

    def test_canonical_fixture_is_admitted_without_execution(self):
        validate_spec(self.spec)
        result = validate(self.record, self.spec, 1)
        self.assertEqual(result["status"], "admitted")
        self.assertTrue(result["admission"])
        self.assertFalse(result["execute"])
        self.assertEqual(result["provider_support"], "unverified")

    def test_unsupported_combination_is_explicitly_blocked(self):
        result = validate(self.unsupported, self.spec, 1)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["classification"], "unsupported_combination")
        self.assertFalse(result["admission"])
        self.assertFalse(result["execute"])

    def test_unknown_capability_blocks_admission(self):
        hostile = copy.deepcopy(self.record)
        hostile["selection"]["requested_capabilities"] = ["checkpoint", "deploy", "edit", "read"]
        hostile["observation"]["capability_status"] = "unsupported"
        hostile["result"].update(status="blocked", admission=False, classification="unsupported_capability")
        self.bind(hostile)
        result = validate(hostile, self.spec, 1)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["classification"], "unsupported_capability")

    def test_unknown_and_incompatible_versions_block(self):
        for field in ("runtime_version", "adapter_version"):
            hostile = copy.deepcopy(self.record)
            hostile["version_negotiation"][field] = "9.9.9"
            hostile["observation"]["version_status"] = "incompatible"
            hostile["result"].update(status="blocked", admission=False, classification="incompatible_version")
            self.bind(hostile)
            result = validate(hostile, self.spec, 1)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["classification"], "incompatible_version")

    def test_crossed_revision_authority_and_private_claims_fail_closed(self):
        mutations = []
        stale = copy.deepcopy(self.record)
        stale["task"]["revision"] = 2
        mutations.append(stale)
        crossed = copy.deepcopy(self.record)
        crossed["authority_snapshot"]["owners"]["awq"] = "coordination"
        mutations.append(crossed)
        private = copy.deepcopy(self.record)
        private["evidence"]["credential"] = "should-never-be-recorded"
        mutations.append(private)
        provider = copy.deepcopy(self.record)
        provider["result"]["provider_support"] = "supported"
        mutations.append(provider)
        unknown = copy.deepcopy(self.record)
        unknown["selection"]["agent_profile"] = "unknown-agent"
        mutations.append(unknown)
        for hostile in mutations:
            self.reject(hostile)

    def test_unknown_fields_and_matrix_tampering_fail_closed(self):
        hostile = copy.deepcopy(self.record)
        hostile["unexpected"] = True
        self.reject(hostile)
        altered = copy.deepcopy(self.spec)
        altered["matrix"][0]["status"] = "unsupported"
        self.reject(self.record, altered)
        altered = copy.deepcopy(self.spec)
        altered["modes"]["local_mock"]["host_profile"] = "local-host"
        self.reject(self.record, altered)

    def test_all_declared_agents_have_local_mock_rows(self):
        agents = {profile["id"] for profile in self.spec["profiles"]["agents"]}
        rows = {row["agent_profile"] for row in self.spec["matrix"] if row["mode"] == "local_mock"}
        self.assertEqual(rows, agents)

    def test_authority_and_failure_contract_is_consumable_by_formal_model(self):
        validate_spec(self.spec)
        ownership = self.spec["authority_ownership"]
        self.assertEqual(set(ownership), {"awc", "awr", "awq", "awg"})
        self.assertFalse(ownership["awr"]["may_approve"])
        self.assertTrue(ownership["awc"]["may_approve"])
        classifications = self.spec["failure_classifications"]
        self.assertEqual(classifications["missing_authority_result"]["outcome"], "blocked")
        self.assertEqual(classifications["ambiguous_authority_result"]["outcome"], "unknown")
        self.assertEqual(classifications["provider_claim_without_evidence"]["authority"], "awr")


if __name__ == "__main__":
    unittest.main()

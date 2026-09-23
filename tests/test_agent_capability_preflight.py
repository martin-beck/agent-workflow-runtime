import copy
import json
import unittest
from pathlib import Path

from scripts.agent_capability_preflight import PreflightError, canonical_bytes, preflight, sha256


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/agent-capability-preflight-v1.json"
FIXTURE = ROOT / "specifications/fixtures/agent-capability-preflight-ar0051-v1.json"


class AgentCapabilityPreflightTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def reject(self, record):
        with self.assertRaises(PreflightError):
            preflight(record, 5)

    def test_offline_eligible_result_keeps_execution_and_live_support_separate(self):
        result = preflight(self.record, 5)
        self.assertEqual(result["benchmark_eligibility"], "eligible")
        self.assertEqual(result["adapter_execution"], "not_performed")
        self.assertEqual(result["live_support"], "unverified")
        self.assertFalse(self.record["result"]["execute"])

    def test_discovery_and_configuration_are_revision_bound(self):
        stale = copy.deepcopy(self.record)
        stale["task"]["revision"] = 4
        self.reject(stale)
        partial = copy.deepcopy(self.record)
        partial["configuration"]["credential_reference"]["status"] = "partial"
        partial["evidence"]["record_digest"] = sha256(canonical_bytes({key: partial[key] for key in partial if key != "evidence"}))
        self.reject(partial)

    def test_hostile_capability_and_host_network_paths_fail_closed(self):
        for field, value in (("requested_capabilities", ["unknown_tool"]), ("host_gate", "mismatch"), ("network_gate", "mismatch")):
            hostile = copy.deepcopy(self.record)
            hostile["configuration"][field] = value
            hostile["evidence"]["record_digest"] = sha256(canonical_bytes({key: hostile[key] for key in hostile if key != "evidence"}))
            self.reject(hostile)

    def test_missing_credential_is_not_eligible_and_provider_unverified_is_explicit(self):
        missing = copy.deepcopy(self.record)
        missing["configuration"]["credential_reference"] = {"status": "missing", "reference_digest": None, "value_absent": True}
        missing["evidence"]["record_digest"] = sha256(canonical_bytes({key: missing[key] for key in missing if key != "evidence"}))
        self.reject(missing)
        self.assertEqual(self.record["result"]["provider_support"], "unverified")
        private = copy.deepcopy(self.record)
        private["configuration"]["credential_reference"]["secret"] = "value"
        self.reject(private)

    def test_spec_is_normative_and_fixture_digest_is_checked(self):
        spec = json.loads(SPEC.read_text(encoding="utf-8"))
        self.assertTrue(spec["normative"])
        tampered = copy.deepcopy(self.record)
        tampered["evidence"]["record_digest"] = sha256(b"tampered")
        self.reject(tampered)


if __name__ == "__main__":
    unittest.main()

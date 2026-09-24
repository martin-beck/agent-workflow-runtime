import copy
import json
import unittest
from pathlib import Path

from scripts.agent_registry import (
    AgentRegistry,
    RegistryError,
    canonical_bytes,
    preflight,
    sha256,
    validate_spec,
)

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/agent-registry-v1.json"
FIXTURE = ROOT / "specifications/fixtures/agent-registry-ar0084-v1.json"


class AgentRegistryTests(unittest.TestCase):
    def setUp(self):
        self.spec = json.loads(SPEC.read_text(encoding="utf-8"))
        self.record = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.registry = AgentRegistry(self.spec)

    @staticmethod
    def bind(record):
        record["evidence"]["record_digest"] = sha256(canonical_bytes({key: value for key, value in record.items() if key != "evidence"}))
        return record

    def reject(self, record=None, spec=None):
        with self.assertRaises(RegistryError):
            preflight(record or self.record, spec or self.spec)

    def test_spec_and_fixture_are_admitted_without_execution(self):
        profiles = validate_spec(self.spec)
        self.assertEqual(set(profiles), {"codex-agent", "opencode-agent", "opendesk-agent", "generic-mock-agent"})
        result = preflight(self.record, self.spec)
        self.assertEqual(result["status"], "admitted")
        self.assertTrue(result["admission"])
        self.assertFalse(result["execute"])
        self.assertEqual(result["provider_verification"], "unverified")

    def test_all_profiles_negotiate_through_the_common_registry(self):
        for profile_id, profile in self.registry.profiles.items():
            request = {
                "profile_id": profile_id,
                "profile_version": profile["version"],
                "adapter_version": profile["adapter_version"],
                "protocol_version": profile["protocol_versions"][0],
                "requested_capabilities": [profile["capabilities"][0]],
            }
            result = self.registry.negotiate(request)
            self.assertEqual(result["catalog_status"], "accepted")
            self.assertEqual(result["capability_status"], "supported")
            self.assertEqual(result["unsupported_capabilities"], [])
            self.assertEqual(result["profile_digest"], profile["profile_digest"])

    def test_unsupported_capability_is_explicit_and_blocks_admission(self):
        hostile = copy.deepcopy(self.record)
        hostile["request"]["requested_capabilities"] = ["checkpoint", "structured_output"]
        hostile["negotiation"]["capability_status"] = "unsupported"
        hostile["negotiation"]["selected_capabilities"] = ["checkpoint"]
        hostile["negotiation"]["unsupported_capabilities"] = ["structured_output"]
        hostile["result"].update(status="blocked", admission=False, classification="unsupported_capability")
        self.bind(hostile)
        result = preflight(hostile, self.spec)
        self.assertEqual(result["classification"], "unsupported_capability")
        self.assertFalse(result["admission"])

    def test_catalog_configuration_mock_and_provider_gates_are_distinct(self):
        missing = copy.deepcopy(self.record)
        missing["configuration"] = {"status": "unknown", "reference": "config:codex-agent:v1", "reference_digest": None, "value_absent": True}
        missing["result"].update(status="blocked", admission=False, classification="configuration_unavailable", configuration_acceptance="unknown")
        self.bind(missing)
        self.assertEqual(preflight(missing, self.spec)["classification"], "configuration_unavailable")
        self.assertEqual(self.record["result"]["catalog_acceptance"], "accepted")
        self.assertEqual(self.record["result"]["configuration_acceptance"], "accepted")
        self.assertEqual(self.record["result"]["local_mock_qualification"], "qualified")
        self.assertEqual(self.record["result"]["provider_verification"], "unverified")

    def test_stale_profile_protocol_revision_and_unknown_profile_fail_closed(self):
        cases = []
        stale = copy.deepcopy(self.record)
        stale["request"]["profile_version"] = "9.9.9"
        cases.append(stale)
        protocol = copy.deepcopy(self.record)
        protocol["request"]["protocol_version"] = "9.9.9"
        cases.append(protocol)
        revision = copy.deepcopy(self.record)
        revision["task"]["revision"] = 2
        cases.append(revision)
        unknown = copy.deepcopy(self.record)
        unknown["request"]["profile_id"] = "unknown-agent"
        cases.append(unknown)
        for case in cases:
            self.reject(case)

    def test_contradictory_and_provider_claims_fail_closed(self):
        contradictory = copy.deepcopy(self.record)
        contradictory["qualification"]["local_mock"]["status"] = "not_qualified"
        self.bind(contradictory)
        self.reject(contradictory)
        provider = copy.deepcopy(self.record)
        provider["qualification"]["provider"] = {"status": "verified", "evidence_digest": None, "execution": "not_performed"}
        self.bind(provider)
        self.reject(provider)
        provider = copy.deepcopy(self.record)
        provider["qualification"]["provider"]["status"] = "verified"
        provider["qualification"]["provider"]["evidence_digest"] = "sha256:" + "a" * 64
        provider["qualification"]["provider"]["execution"] = "supplied_observation"
        self.bind(provider)
        self.reject(provider)

    def test_private_values_unknown_fields_and_tampered_digests_fail_closed(self):
        private = copy.deepcopy(self.record)
        private["configuration"]["credential"] = "secret"
        self.reject(private)
        unknown = copy.deepcopy(self.record)
        unknown["unexpected"] = True
        self.reject(unknown)
        altered = copy.deepcopy(self.spec)
        altered["profiles"][0]["capabilities"].append("deploy")
        self.reject(self.record, altered)
        altered_record = copy.deepcopy(self.record)
        altered_record["registry_digest"] = "sha256:" + "b" * 64
        self.reject(altered_record)

    def test_profile_digest_and_local_qualification_digest_are_bound(self):
        altered = copy.deepcopy(self.spec)
        altered["profiles"][0]["profile_digest"] = "sha256:" + "c" * 64
        with self.assertRaises(RegistryError):
            validate_spec(altered)
        altered_record = copy.deepcopy(self.record)
        altered_record["qualification"]["local_mock"]["evidence_digest"] = "sha256:" + "d" * 64
        self.bind(altered_record)
        self.reject(altered_record)

    def test_registry_never_executes_or_claims_provider_support(self):
        self.assertEqual(self.spec["offline_boundary"]["network"], "disabled")
        self.assertEqual(self.spec["offline_boundary"]["provider"], "not_performed")
        self.assertEqual(self.spec["offline_boundary"]["llm"], "not_performed")
        self.assertFalse(self.record["result"]["execute"])
        self.assertEqual(self.record["result"]["provider_support"], "unverified")


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.security_privacy_supply_chain import AssuranceError, canonical_bytes, sha256, validate
from scripts.check_security_privacy_supply_chain import load

ROOT = Path(__file__).parents[1]


class SecurityPrivacySupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.record = load(ROOT / "specifications/fixtures/security-privacy-supply-chain-ar0025-v1.json")

    def reject(self, record):
        with self.assertRaises(AssuranceError):
            validate(record)

    def test_positive_fixture_is_revision_bound_and_digest_consistent(self):
        result = validate(self.record)
        self.assertEqual(result["task_revision"], 1)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["publication"], "not_performed")
        self.assertEqual(result["dependencies"], 1)
        self.assertEqual(self.record["evidence"][0]["digest"], sha256(canonical_bytes(self.record["secret_handling"])))

    def test_hostile_privacy_and_credential_boundaries(self):
        private = copy.deepcopy(self.record); private["public_evidence"]["raw_output"] = "must not enter evidence"; self.reject(private)
        credential = copy.deepcopy(self.record); credential["secret_handling"]["storage"] = "password=leak"; self.reject(credential)
        private_path = copy.deepcopy(self.record); private_path["session"] = "SES-/home/private"; self.reject(private_path)
        unknown = copy.deepcopy(self.record); unknown["redaction"]["extra"] = False; self.reject(unknown)

    def test_hostile_provenance_and_least_privilege(self):
        floating = copy.deepcopy(self.record); floating["dependency_provenance"]["dependencies"][0]["version"] = "latest"; self.reject(floating)
        missing_integrity = copy.deepcopy(self.record); missing_integrity["dependency_provenance"]["dependencies"][0]["integrity_digest"] = "sha256:" + "0" * 63; self.reject(missing_integrity)
        network = copy.deepcopy(self.record); network["least_privilege"]["granted"].append("network"); self.reject(network)
        unsigned = copy.deepcopy(self.record); unsigned["dependency_provenance"]["dependencies"][0]["source"] = "registry@latest"; self.reject(unsigned)

    def test_hostile_replay_stale_cross_binding_and_digest_tamper(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["evidence"][1] = copy.deepcopy(replay["evidence"][0]); self.reject(replay)
        crossed = copy.deepcopy(self.record); crossed["worktree"]["key"] = "agent-workflow-runtime-0024"; self.reject(crossed)
        tampered = copy.deepcopy(self.record); tampered["evidence"][0]["digest"] = "sha256:" + "0" * 64; self.reject(tampered)


if __name__ == "__main__":
    unittest.main()

import copy
import json
import unittest
from pathlib import Path

from scripts.production_security_hardening import SecurityError, digest, validate

ROOT = Path(__file__).parents[1]


class ProductionSecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / "specifications/fixtures/production-security-hardening-ar0057-v1.json").read_text())

    def reject(self, mutate):
        record = copy.deepcopy(self.record)
        mutate(record)
        with self.assertRaises(SecurityError):
            validate(record, 5)

    def test_positive_fixture_is_revision_bound_and_fail_closed(self):
        result = validate(self.record, 5)
        self.assertEqual(result["controls"], 9)
        self.assertEqual(result["dependencies"], 1)
        self.assertEqual(result["live_review"], "required")
        self.assertEqual(result["network"], "disabled")

    def test_supply_chain_signature_sbom_and_key_rotation(self):
        self.reject(lambda r: r["evidence"]["dependencies"][0].update(signature="missing"))
        self.reject(lambda r: r["evidence"]["dependencies"][0].update(dco="unsigned"))
        self.reject(lambda r: r["evidence"]["dependencies"][0].update(sbom_digest="sha256:" + "0" * 63))
        self.reject(lambda r: r["evidence"]["keys"].update(rotation_due=True))
        self.reject(lambda r: r["evidence"]["keys"].update(old_keys_revoked=False))

    def test_secret_egress_sandbox_privacy_and_degradation(self):
        self.reject(lambda r: r["evidence"]["secrets"].update(values_absent=False))
        self.reject(lambda r: r["evidence"]["privilege"]["granted"].append("network"))
        self.reject(lambda r: r["evidence"]["sandbox"].update(egress="allow_all"))
        self.reject(lambda r: r["evidence"]["privacy"].update(raw_payloads="present"))
        self.reject(lambda r: r["evidence"]["degradation"].update(audit_failure="continue"))

    def test_audit_tampering_revision_cross_binding_and_record_digest(self):
        self.reject(lambda r: r["audit"][1].update(previous_digest=digest("genesis")))
        self.reject(lambda r: r["task"].update(revision=4))
        self.reject(lambda r: r["worktree"].update(key="agent-workflow-runtime-0056"))
        self.reject(lambda r: r["evidence"].update(record_digest=digest("tampered")))


if __name__ == "__main__":
    unittest.main()

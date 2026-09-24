import copy
import json
import unittest
from pathlib import Path

from scripts.executable_security import ExecutableSecurityError, validate

FIXTURE = (
    Path(__file__).parents[1]
    / "specifications/fixtures/executable-security-ar0092-v1.json"
)


class ExecutableSecurityAR0092Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text())

    def test_fixture_passes_offline_fail_closed_contract(self):
        result = validate(self.record)
        self.assertTrue(result["fail_closed"])
        self.assertEqual(result["network"], "disabled")

    def test_missing_signature_fails_closed(self):
        record = copy.deepcopy(self.record)
        record["artifact"]["signature_digest"] = "missing"
        with self.assertRaisesRegex(
            ExecutableSecurityError, "invalid_signature_digest"
        ):
            validate(record)

    def test_egress_allowlist_cannot_open(self):
        record = copy.deepcopy(self.record)
        record["egress"]["allowlist"] = ["provider"]
        with self.assertRaisesRegex(ExecutableSecurityError, "egress_fail_open"):
            validate(record)

    def test_secret_value_is_rejected(self):
        record = copy.deepcopy(self.record)
        record["secret_refs"]["references"] = ["secret-value:bad"]
        with self.assertRaisesRegex(
            ExecutableSecurityError, "secret_reference_violation"
        ):
            validate(record)


if __name__ == "__main__":
    unittest.main()

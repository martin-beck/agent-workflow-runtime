import copy
import json
import unittest
from pathlib import Path

from scripts.check_admission import AdmissionError, canonical_bytes, load_json, sha256, validate_admission, validate_spec


ROOT = Path(__file__).parents[1]
SPEC_PATH = ROOT / "specifications" / "runtime-charter-v1.json"


def valid_admission(spec):
    digest = "sha256:" + sha256(canonical_bytes(spec))
    return {
        "schema_version": 1,
        "task": {"id": "AR-0001", "revision": 5},
        "specification": {"id": spec["specification_id"], "version": spec["version"], "sha256": digest},
        "evidence": [{"id": "EV-AR0001-CHECK", "digest": "sha256:" + "1" * 64}],
        "decision": "admit",
    }


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_json(SPEC_PATH)
        self.admission = valid_admission(self.spec)

    def assert_rejected(self, admission=None, spec=None, expected_revision=5, seen=()):
        with self.assertRaises(AdmissionError):
            validate_admission(admission or self.admission, spec or self.spec, expected_revision, seen)

    def test_valid_spec_and_admission(self):
        validate_spec(self.spec)
        result = validate_admission(self.admission, self.spec, 5)
        self.assertEqual(result["decision"], "admit")

    def test_malformed_specification(self):
        malformed = copy.deepcopy(self.spec)
        del malformed["charter"]
        with self.assertRaises(AdmissionError):
            validate_spec(malformed)

    def test_missing_authority(self):
        malformed = copy.deepcopy(self.spec)
        malformed["authority_matrix"] = [entry for entry in malformed["authority_matrix"] if entry["authority"] != "guidance"]
        # Missing an authority is invalid even when no domain happens to overlap.
        malformed["charter"]["runtime_must_not_own"].append("oracle decisions")
        self.assert_rejected(spec=malformed)

    def test_unsupported_authority_overlap(self):
        malformed = copy.deepcopy(self.spec)
        malformed["authority_matrix"].append({"authority": "unrecognized", "domains": ["task identity"]})
        self.assert_rejected(spec=malformed)

    def test_stale_revision_and_digest(self):
        self.assert_rejected(expected_revision=4)
        stale = copy.deepcopy(self.admission)
        stale["specification"]["sha256"] = "sha256:" + "0" * 64
        self.assert_rejected(admission=stale)

    def test_replay_and_duplicate_evidence(self):
        duplicate = copy.deepcopy(self.admission)
        duplicate["evidence"].append(copy.deepcopy(duplicate["evidence"][0]))
        self.assert_rejected(admission=duplicate)
        self.assert_rejected(seen={"EV-AR0001-CHECK"})

    def test_prohibited_private_data(self):
        private = copy.deepcopy(self.admission)
        private["evidence"][0]["note"] = "/home/example/secret.log"
        self.assert_rejected(admission=private)

    def test_unknown_extra_fields_are_rejected_where_binding_is_unsafe(self):
        malformed = copy.deepcopy(self.admission)
        malformed["evidence"][0]["transcript"] = "not public"
        self.assert_rejected(admission=malformed)


if __name__ == "__main__":
    unittest.main()

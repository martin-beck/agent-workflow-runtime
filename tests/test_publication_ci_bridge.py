import copy
import unittest
from pathlib import Path

from scripts.publication_ci_bridge import BridgeError, canonical_bytes, project, sha256, validate
from scripts.check_publication_ci_bridge import load

ROOT = Path(__file__).parents[1]


class PublicationCiBridgeTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/publication-ci-bridge-v1.json")
        self.record = load(ROOT / "specifications/fixtures/publication-ci-bridge-ar0021-v1.json")
        self.evidence = load(ROOT / "specifications/fixtures/publication-ci-evidence-ar0021-v1.json")

    def reject(self, record=None):
        with self.assertRaises(BridgeError):
            validate(record or self.record)

    def test_positive_fixture_binds_signed_head_handoff_and_unverified_ci(self):
        result = validate(self.record)
        self.assertEqual(result["head"], self.record["branch"]["head"])
        self.assertEqual(result["ci"], "unverified")
        self.assertEqual(result["merge_handoff"], "ready")
        self.assertEqual(result["publication"], "not_performed")
        self.assertEqual(self.evidence["record_digest"], sha256(canonical_bytes(self.record)))
        self.assertEqual(self.evidence["projection"], project(self.record, self.evidence["specification_digest"]))

    def test_hostile_stale_replay_unknown_private_cases(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["evidence"][1] = copy.deepcopy(replay["evidence"][0]); self.reject(replay)
        unknown = copy.deepcopy(self.record); unknown["ci"]["extra"] = "bad"; self.reject(unknown)
        private = copy.deepcopy(self.record); private["branch"]["name"] = "/home/private/branch"; self.reject(private)

    def test_hostile_wrong_head_unsigned_and_unverified_cases(self):
        for field in ("review", "merge_handoff", "ci", "publication"):
            wrong = copy.deepcopy(self.record); wrong[field]["target_head"] = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"; self.reject(wrong)
        unsigned = copy.deepcopy(self.record); unsigned["commit"]["signature"]["status"] = "missing"; self.reject(unsigned)
        unsigned_dco = copy.deepcopy(self.record); unsigned_dco["commit"]["dco"]["status"] = "missing"; self.reject(unsigned_dco)
        verified = copy.deepcopy(self.record); verified["ci"]["verification"] = "verified"; self.reject(verified)
        merged = copy.deepcopy(self.record); merged["merge_handoff"]["status"] = "merged"; self.reject(merged)


if __name__ == "__main__":
    unittest.main()

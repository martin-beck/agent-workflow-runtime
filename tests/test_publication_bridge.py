import copy
import unittest
from pathlib import Path

from scripts.publication_bridge import PublicationError, canonical_bytes, project_evidence, sha256, validate_record
from scripts.check_publication_bridge import load


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/publication-bridge-v1.json"
RECORD = ROOT / "specifications/fixtures/publication-bridge-ar0012-v1.json"
EVIDENCE = ROOT / "specifications/fixtures/publication-evidence-ar0012-v1.json"


class PublicationBridgeTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.record, self.evidence = load(SPEC), load(RECORD), load(EVIDENCE)

    def reject(self, record=None, revision=3):
        with self.assertRaises(PublicationError):
            validate_record(record or self.record, revision)

    def test_positive_fixture_is_revision_bound_and_canonical(self):
        result = validate_record(self.record, 3)
        self.assertEqual(result["head"], self.record["commit"]["id"])
        self.assertEqual(result["merge"], "not_performed")
        self.assertEqual(self.evidence["record_digest"], sha256(canonical_bytes(self.record)))
        self.assertEqual(self.evidence["projection"], project_evidence(self.record, self.evidence["specification_digest"]))
        unsigned = dict(self.evidence)
        unsigned.pop("evidence_digest")
        self.assertEqual(self.evidence["evidence_digest"], sha256(canonical_bytes(unsigned)))

    def test_hostile_stale_and_replay_cases(self):
        stale = copy.deepcopy(self.record); stale["task"]["revision"] = 2; self.reject(stale)
        replay = copy.deepcopy(self.record); replay["evidence"][1] = copy.deepcopy(replay["evidence"][0]); self.reject(replay)
        duplicate_digest = copy.deepcopy(self.record); duplicate_digest["evidence"][1]["digest"] = duplicate_digest["evidence"][0]["digest"]; self.reject(duplicate_digest)

    def test_hostile_unknown_private_wrong_head_and_unsigned_cases(self):
        unknown = copy.deepcopy(self.record); unknown["review"]["extra"] = "bad"; self.reject(unknown)
        private = copy.deepcopy(self.record); private["branch"]["name"] = "/home/private/branch"; self.reject(private)
        wrong_head = copy.deepcopy(self.record); wrong_head["review"]["target_head"] = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"; self.reject(wrong_head)
        unsigned = copy.deepcopy(self.record); unsigned["commit"]["signature"]["status"] = "missing"; self.reject(unsigned)
        unsigned_dco = copy.deepcopy(self.record); unsigned_dco["commit"]["dco"]["status"] = "missing"; self.reject(unsigned_dco)

    def test_merge_and_publication_cannot_claim_side_effects(self):
        merged = copy.deepcopy(self.record); merged["merge"]["status"] = "merged"; self.reject(merged)
        published = copy.deepcopy(self.record); published["publication"]["status"] = "published"; self.reject(published)


if __name__ == "__main__":
    unittest.main()

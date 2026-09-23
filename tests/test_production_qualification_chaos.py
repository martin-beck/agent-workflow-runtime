import copy
import json
import unittest
from pathlib import Path

from scripts.production_qualification_chaos import QualificationError, digest, validate
from scripts.check_production_qualification_chaos import validate_spec

ROOT = Path(__file__).parents[1]

class ProductionQualificationChaosTests(unittest.TestCase):
    def setUp(self):
        self.spec = json.loads((ROOT / "specifications/production-qualification-chaos-v1.json").read_text())
        self.record = json.loads((ROOT / "specifications/fixtures/production-qualification-chaos-ar0059-v1.json").read_text())

    def reject(self, mutate):
        record = copy.deepcopy(self.record); mutate(record)
        with self.assertRaises(QualificationError): validate(record)

    def test_catalog_thresholds_and_digest_replay(self):
        validate_spec(self.spec, 5)
        result = validate(self.record)
        self.assertEqual(result["scenarios"], 12)
        self.assertEqual(result["release"], "blocked_pending_live_evidence")
        self.assertEqual(self.record["evidence"]["specification_digest"], digest(self.spec))

    def test_hostile_stale_crossed_replay_privacy_threshold_and_live_claims_fail_closed(self):
        self.reject(lambda r: r["task"].update(revision=4))
        self.reject(lambda r: r["observations"][1].update(scenario=r["observations"][0]["scenario"]))
        self.reject(lambda r: r["observations"][0].update(session_id="SES-OTHER"))
        self.reject(lambda r: r["metrics"][0].update(value=999))
        self.reject(lambda r: r["metrics"][0].update(prompt="raw"))
        self.reject(lambda r: r["result"].update(provider="success"))
        self.reject(lambda r: r["observations"][0].update(fence="reused_worker"))

if __name__ == "__main__":
    unittest.main()

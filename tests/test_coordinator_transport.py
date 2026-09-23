import copy
import unittest
from pathlib import Path

from scripts.check_coordinator_transport import check, load
from scripts.coordinator_transport import TransportError

ROOT = Path(__file__).parents[1]


class CoordinatorTransportTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/coordinator-transport-v1.json")
        self.record = load(ROOT / "specifications/fixtures/coordinator-transport-ar0046-v1.json")

    def test_transcript_qualifies_offline_and_unknown_outcome_is_explicit(self):
        result = check(self.spec, self.record, 5)
        self.assertEqual(result["final_server_revision"], 7)
        self.assertEqual(result["live_verification"], "unverified")

    def test_crossed_binding_and_tampered_evidence_fail_closed(self):
        for mutate in (lambda r: r["transcript"][1].update(event_digest="sha256:" + "9" * 64), lambda r: r["evidence"].update(network="performed")):
            record = copy.deepcopy(self.record)
            mutate(record)
            with self.assertRaises(TransportError):
                check(self.spec, record, 5)


if __name__ == "__main__":
    unittest.main()

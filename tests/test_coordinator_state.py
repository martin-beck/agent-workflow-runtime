import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_coordinator_state import check_record, check_spec, load
from scripts.coordinator_state import CoordinatorError, CoordinatorHarness

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/coordinator-live-state-v1.json"
FIXTURE = ROOT / "specifications/fixtures/coordinator-live-state-ar0029-v1.json"


class CoordinatorStateTests(unittest.TestCase):
    def test_fixture_and_spec_are_accepted(self):
        spec, record = load(SPEC), load(FIXTURE)
        check_spec(spec)
        result = check_record(record, spec, 3)
        self.assertEqual(result["events"], 4)
        self.assertEqual(result["live_verification"], "unverified")

    def test_file_backed_round_trip_and_idempotent_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.json")
            h = CoordinatorHarness(path)
            first = h.claim("OP-AR0029-X", expected_revision=3, session="SES-AR0029-X", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T19:00:00+00:00")
            replay = h.claim("OP-AR0029-X", expected_revision=3, session="SES-AR0029-X", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T19:00:00+00:00")
            self.assertEqual(first, replay)
            self.assertEqual(len(h.data["events"]), 1)
            loaded = CoordinatorHarness(path)
            self.assertEqual(loaded.data["task"]["revision"], 4)

    def test_hostile_stale_crossed_replay_privacy_and_corruption(self):
        h = CoordinatorHarness(now="2026-09-23T18:00:00+00:00")
        with self.assertRaises(CoordinatorError):
            h.claim("OP-AR0029-X", expected_revision=2, session="SES-AR0029-X", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T19:00:00+00:00")
        h.claim("OP-AR0029-X", expected_revision=3, session="SES-AR0029-X", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T19:00:00+00:00")
        with self.assertRaises(CoordinatorError):
            h.heartbeat("OP-AR0029-Y", expected_revision=4, session="SES-OTHER", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T20:00:00+00:00")
        h.now = "2026-09-23T20:00:01+00:00"
        with self.assertRaises(CoordinatorError):
            h.heartbeat("OP-AR0029-Z", expected_revision=4, session="SES-AR0029-X", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T21:00:00+00:00")
        with self.assertRaises(CoordinatorError):
            h.claim("OP-AR0029-X", expected_revision=3, session="SES-AR0029-X", owner="WRK-AR0029-X", lease="LSE-AR0029-X", claim_expires="2026-09-23T20:00:00+00:00")
        private = copy.deepcopy(h.data)
        private["events"][0]["credential"] = "forbidden"
        private["events"][0]["event_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(CoordinatorError):
            h2 = CoordinatorHarness(); h2.data = private; h2._validate_document()

    def test_checker_rejects_stale_and_tampered_fixture(self):
        spec, record = load(SPEC), load(FIXTURE)
        stale = copy.deepcopy(record); stale["task"]["revision"] = 5
        with self.assertRaises(CoordinatorError): check_record(stale, spec, 3)
        tampered = copy.deepcopy(record); tampered["events"][1]["claim_expires"] = "2026-09-23T21:00:00+00:00"
        with self.assertRaises(CoordinatorError): check_record(tampered, spec, 3)


if __name__ == "__main__":
    unittest.main()

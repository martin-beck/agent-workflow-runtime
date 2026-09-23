import copy
import unittest
from pathlib import Path

from scripts.check_durable_recovery import load, validate_fixture, validate_spec
from scripts.durable_recovery import DurableSession, RecoveryError

ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications/durable-recovery-v1.json"
FIXTURE = ROOT / "specifications/fixtures/durable-recovery-ar0036-v1.json"


class DurableRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(SPEC)
        self.fixture = load(FIXTURE)

    def test_fixture_replays_revision_three_recovery(self):
        validate_spec(self.spec)
        result = validate_fixture(self.fixture, 3)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["records"], 3)
        self.assertEqual(result["head_digest"], self.fixture["expected_head_digest"])

    def test_hostile_revision_private_and_unknown_actions_reject(self):
        with self.assertRaises(RecoveryError):
            validate_fixture(self.fixture, 2)
        private = copy.deepcopy(self.fixture)
        private["actions"][0]["payload"]["token"] = "forbidden"
        with self.assertRaises(RecoveryError):
            validate_fixture(private, 3)
        unknown = copy.deepcopy(self.fixture)
        unknown["actions"][0]["kind"] = "commit"
        with self.assertRaises(RecoveryError):
            validate_fixture(unknown, 3)

    def test_model_rejects_changed_replay_and_old_fence(self):
        session = DurableSession(task_revision=3, session_id="SES-AR0036-X", worker_id="WRK-AR0036-A", lease_id="LSE-AR0036-A")
        session.append(operation_id="OP-AR0036-ONE", event="start", payload={"phase": "recovery"})
        with self.assertRaises(RecoveryError):
            session.append(operation_id="OP-AR0036-ONE", event="start", payload={"phase": "changed"})
        with self.assertRaises(RecoveryError):
            session.append(operation_id="OP-AR0036-OLD", event="progress", payload={}, worker="WRK-AR0036-OLD", lease="LSE-AR0036-OLD", fence=0)


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.asb_pilot import PilotError, validate_record
from scripts.check_asb_pilot import load

ROOT = Path(__file__).parents[1]


class AsbPilotTests(unittest.TestCase):
    def setUp(self):
        self.record = load(ROOT / "specifications/fixtures/asb-pilot-ar0044-v1.json")

    def test_offline_composed_pilot_is_qualified_without_run(self):
        result = validate_record(self.record, 3)
        self.assertEqual(result["workflow_observations"], 9)
        self.assertEqual(result["asb_observations"], 7)
        self.assertEqual(result["asb_run"], "not_performed")
        self.assertFalse(result["execute"])

    def test_hostile_revision_run_and_replay_inputs_fail_closed(self):
        mutations = (
            lambda r: r["task"].update(revision=2),
            lambda r: r["asb"][3].update(status="observed"),
            lambda r: r["asb"][1].update(depends_on=[]),
            lambda r: r["workflow"][0].update(evidence_digest="sha256:" + "0" * 64),
            lambda r: r["asb"][0].update(observation_id=r["asb"][1]["observation_id"]),
            lambda r: r["terminal"].update(execute=True),
            lambda r: r["asb"][2].update(prompt="not allowed"),
        )
        for mutation in mutations:
            changed = copy.deepcopy(self.record)
            mutation(changed)
            with self.assertRaises(PilotError):
                validate_record(changed, 3)

    def test_expected_revision_is_exactly_three(self):
        with self.assertRaises(PilotError):
            validate_record(self.record, 4)


if __name__ == "__main__":
    unittest.main()

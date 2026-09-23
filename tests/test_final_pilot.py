import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_final_pilot import load, validate_spec
from scripts.final_pilot import FinalPilotError, validate

ROOT = Path(__file__).parents[1]


class FinalPilotTests(unittest.TestCase):
    def setUp(self):
        self.spec = load(ROOT / "specifications/final-pilot-operational-acceptance-v1.json")
        self.record = load(ROOT / "specifications/fixtures/final-pilot-ar0060-v1.json")

    def test_all_gates_compose_to_offline_qualification(self):
        validate_spec(self.spec, 5)
        result = validate(self.record, 5)
        self.assertEqual(result["gates"], 9)
        self.assertEqual(result["operational_acceptance"], "blocked_pending_live_evidence")
        self.assertFalse(result["execute"])

    def test_hostile_missing_failed_reordered_and_live_claims_fail_closed(self):
        mutations = (
            lambda r: r["gates"].pop(),
            lambda r: r["gates"][3].update(status="failed"),
            lambda r: r["gates"].reverse(),
            lambda r: r["gates"][0].update(evidence_digest="sha256:" + "0" * 64),
            lambda r: r["gates"][2].update(depends_on=[]),
            lambda r: r["terminal"].update(execute=True),
            lambda r: r["terminal"].update(provider="performed"),
            lambda r: r["gates"][0].update(secret="nope"),
            lambda r: r["task"].update(revision=4),
        )
        for mutation in mutations:
            changed = copy.deepcopy(self.record)
            mutation(changed)
            with self.assertRaises(FinalPilotError):
                validate(changed, 5)

    def test_revision_is_exact(self):
        with self.assertRaises(FinalPilotError):
            validate(self.record, 4)

    def test_specification_digest_is_bound_by_checker(self):
        changed = copy.deepcopy(self.spec)
        changed["title"] = "changed"
        from scripts.check_final_pilot import main
        with tempfile.TemporaryDirectory() as directory:
            spec_path = Path(directory) / "spec.json"
            fixture_path = Path(directory) / "fixture.json"
            spec_path.write_text(json.dumps(changed), encoding="utf-8")
            fixture_path.write_text(json.dumps(self.record), encoding="utf-8")
            self.assertEqual(main(["--spec", str(spec_path), "--fixture", str(fixture_path), "--expected-revision", "5"]), 1)


if __name__ == "__main__":
    unittest.main()

import copy
import unittest
from pathlib import Path

from scripts.check_opencode_live_adapter import load_json, validate_fixture
from scripts.opencode_live_adapter import OpenCodeLiveError

ROOT = Path(__file__).parents[1]


class OpenCodeLiveAdapterTests(unittest.TestCase):
    def test_fixture_is_offline_and_revision_bound(self):
        record = load_json(ROOT / "specifications/fixtures/opencode-live-adapter-ar0034-v1.json")
        result = validate_fixture(record)
        self.assertFalse(result["execute"])
        self.assertEqual(result["task_revision"], 3)

    def test_changed_response_and_crossed_binding_fail(self):
        record = load_json(ROOT / "specifications/fixtures/opencode-live-adapter-ar0034-v1.json")
        for mutation in (lambda value: value["response"].update(status="rejected"), lambda value: value["trace"][0]["binding"]["session"].update(id="SES-OTHER")):
            changed = copy.deepcopy(record)
            mutation(changed)
            with self.assertRaises(OpenCodeLiveError):
                validate_fixture(changed)


if __name__ == "__main__":
    unittest.main()

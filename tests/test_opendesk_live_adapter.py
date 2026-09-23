import copy
import unittest
from pathlib import Path

from scripts.check_opendesk_live_adapter import ContractError, load, validate_record, validate_spec


ROOT = Path(__file__).parents[1]
SPEC = ROOT / "specifications" / "opendesk-live-provider-v1.json"
FIXTURE = ROOT / "specifications" / "fixtures" / "opendesk-live-provider-ar0035-v1.json"


class OpenDeskLiveAdapterTests(unittest.TestCase):
    def test_fixture_is_valid_and_event_digest_tampering_is_rejected(self):
        spec = load(SPEC)
        record = load(FIXTURE)
        validate_spec(spec)
        result = validate_record(record, spec, 3)
        self.assertEqual(result["events"], 8)
        hostile = copy.deepcopy(record)
        hostile["events"][3]["request_digest"] = "sha256:" + "9" * 64
        with self.assertRaises(ContractError):
            validate_record(hostile, spec, 3)


if __name__ == "__main__":
    unittest.main()

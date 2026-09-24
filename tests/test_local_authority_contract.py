import json
import unittest
from pathlib import Path

from scripts.check_local_authority_contract import check


class LocalAuthorityContractTests(unittest.TestCase):
    def test_contract_and_fixtures_are_complete(self):
        first = check()
        self.assertEqual(first, check())
        self.assertEqual(first["authorities"], 4)
        self.assertEqual(first["hostile_cases"], 5)

    def test_worker_mutation_prohibition_is_normative(self):
        spec = json.loads(Path("specifications/local-authority-bridge-v1.json").read_text())
        self.assertEqual(set(spec["request"]["worker_forbidden_kinds"]), {"decision", "test", "specification"})


if __name__ == "__main__":
    unittest.main()

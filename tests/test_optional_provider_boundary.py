import unittest

from scripts.check_optional_provider_boundary import check


class OptionalProviderBoundaryTests(unittest.TestCase):
    def test_baseline_and_provider_evidence_are_separate(self):
        result = check()
        self.assertEqual(result["status"], "qualified_local_boundary")
        self.assertEqual(result["provider"], "not_performed")
        self.assertEqual(result["hostile_cases"], 5)


if __name__ == "__main__":
    unittest.main()

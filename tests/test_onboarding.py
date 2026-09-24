import unittest

from scripts.check_onboarding import check


class OnboardingTests(unittest.TestCase):
    def test_documented_path_is_machine_checked(self):
        first = check()
        self.assertEqual(first, check())
        self.assertEqual(first["commands"], 7)
        self.assertEqual(first["network"], "disabled")


if __name__ == "__main__":
    unittest.main()

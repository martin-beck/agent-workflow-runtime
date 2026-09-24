import os
import stat
import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.install import install
from awr_cli.security import check


class SecurityTests(unittest.TestCase):
    def test_secure_home_and_managed_files_pass(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"
            install(home)
            self.assertEqual(check(home)["status"], "secure")

    def test_open_permissions_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"
            install(home)
            home.chmod(0o755)
            with self.assertRaisesRegex(CliError, "permissions_too_open"):
                check(home)
            home.chmod(0o700)
            (home / "config.json").unlink()
            (home / "config.json").symlink_to(Path(root) / "outside")
            with self.assertRaisesRegex(CliError, "unsafe"):
                check(home)

    def test_credential_keys_and_oversized_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"
            install(home)
            (home / "config.json").write_text('{"token":"must-not-be-here"}', encoding="utf-8")
            with self.assertRaisesRegex(CliError, "credential"):
                check(home)


if __name__ == "__main__":
    unittest.main()

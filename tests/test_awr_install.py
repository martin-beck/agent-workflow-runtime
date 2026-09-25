import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from awr_cli.cli import CliError, main
from awr_cli.install import doctor, install, rollback, uninstall


class AwrInstallTests(unittest.TestCase):
    def test_install_doctor_and_space_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "runtime home with spaces"
            self.assertEqual(doctor(home)["status"], "not_installed")
            self.assertEqual(install(home)["status"], "installed")
            self.assertEqual(doctor(home)["status"], "healthy")

    def test_repair_preserves_custom_config_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            install(home)
            config = home / "config.json"
            config.write_text('{"schema_version":1,"custom":"keep"}', encoding="utf-8")
            sentinel = home / "unrelated.txt"
            sentinel.write_text("untouched", encoding="utf-8")
            (home / "state.json").unlink()
            self.assertEqual(install(home, repair=True)["status"], "repaired")
            self.assertEqual(json.loads(config.read_text())["custom"], "keep")
            self.assertEqual(sentinel.read_text(), "untouched")

    def test_corrupt_config_and_partial_marker_fail_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            (home / "config.json").write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(CliError, "config_corrupt"):
                install(home)
            self.assertEqual((home / "config.json").read_text(), "{broken")
            (home / "config.json").unlink()
            (home / "install.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(CliError, "install_marker_invalid"):
                install(home, repair=True)
            self.assertEqual((home / "install.json").read_text(), "{}")

    def test_upgrade_rollback_and_uninstall_preserve_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            install(home)
            self.assertEqual(install(home, upgrade=True)["status"], "upgraded")
            self.assertEqual(rollback(home)["status"], "rolled_back")
            user_data = home / "config.json"
            self.assertEqual(uninstall(home)["status"], "uninstalled")
            self.assertTrue(user_data.exists())
            self.assertFalse((home / "install.json").exists())

    def test_interrupted_first_bootstrap_removes_only_files_it_created(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            original = __import__("awr_cli.install", fromlist=["_atomic_write"])._atomic_write
            calls = 0

            def interrupted(path, data):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("simulated interruption")
                return original(path, data)

            with patch("awr_cli.install._atomic_write", side_effect=interrupted):
                with self.assertRaisesRegex(CliError, "bootstrap_interrupted"):
                    install(home)
            self.assertEqual(list(home.iterdir()), [])

    def test_permission_failure_and_stable_version_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            with patch("awr_cli.install.os.access", return_value=False):
                with self.assertRaisesRegex(CliError, "runtime_home_not_writable"):
                    install(home)
        with patch("sys.stdout") as output:
            self.assertEqual(main(["version"]), 0)
        self.assertIn('"version":"0.1.10"', "".join(call.args[0] for call in output.write.call_args_list))


if __name__ == "__main__":
    unittest.main()

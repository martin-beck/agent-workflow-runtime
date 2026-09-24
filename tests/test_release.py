import hashlib
import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.release import verify_artifact


class ReleaseTests(unittest.TestCase):
    def test_exact_artifact_provenance_and_rollback_target(self):
        with tempfile.TemporaryDirectory() as root:
            artifact = Path(root) / "runtime.whl"; artifact.write_bytes(b"deterministic-wheel")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            result = verify_artifact(artifact, version="0.1.1", source_commit="a" * 40, expected_sha256=digest, rollback_version="0.1.0")
            self.assertEqual(result["status"], "qualified")
            self.assertEqual(result["publication"], "not_performed")

    def test_digest_symlink_and_rollback_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); artifact = root / "runtime.whl"; artifact.write_bytes(b"wheel")
            with self.assertRaisesRegex(CliError, "digest"):
                verify_artifact(artifact, version="0.1.1", source_commit="a" * 40, expected_sha256="0" * 64)
            link = root / "link"; link.symlink_to(artifact)
            with self.assertRaisesRegex(CliError, "artifact_invalid"):
                verify_artifact(link, version="0.1.1", source_commit="a" * 40, expected_sha256="0" * 64)
            with self.assertRaisesRegex(CliError, "rollback"):
                verify_artifact(artifact, version="0.1.1", source_commit="a" * 40, expected_sha256=hashlib.sha256(b"wheel").hexdigest(), rollback_version="0.1.1")


if __name__ == "__main__":
    unittest.main()

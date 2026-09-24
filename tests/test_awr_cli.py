import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError, initialize_mock, make_plan, validate_manifest


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "project-manifest.yaml"


class AwrCliTests(unittest.TestCase):
    def setUp(self):
        self.raw = MANIFEST.read_bytes()
        self.manifest, self.revision = validate_manifest(self.raw)

    def test_repository_manifest_validates_with_exact_byte_revision(self):
        self.assertEqual(self.revision, "sha256:" + hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(self.manifest["project"]["name"], "agent-workflow-runtime")

    def test_dry_run_is_deterministic_and_bound_to_manifest_revision(self):
        first = make_plan(self.manifest, self.revision, "mock/workspace")
        self.assertEqual(first, make_plan(self.manifest, self.revision, "mock/workspace"))
        self.assertTrue(first["dry_run"])
        self.assertEqual(first["project_revision"], self.revision)
        self.assertEqual(first["effects"]["coordinator"], "not_performed")

    def test_initializer_creates_only_local_mock_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "workspace"
            result = initialize_mock(self.manifest, self.revision, target)
            state = json.loads((target / ".awr/local-mock/state.json").read_text())
            self.assertEqual(result["status"], "created")
            self.assertEqual(state["project_revision"], self.revision)
            self.assertEqual(state["provider"], "not_performed")
            self.assertFalse((target / "coordinator").exists())
            self.assertFalse((target / "awq").exists())

    def test_rejects_duplicate_unknown_credentials_and_oversized_manifest(self):
        invalid = (
            self.raw + b"schema: 1\n",
            self.raw + b"credentials: secret\n",
            b"schema: 1\nschema: 1\n",
            b"x" * 65537,
        )
        for raw in invalid:
            with self.subTest(size=len(raw)):
                with self.assertRaises(CliError):
                    validate_manifest(raw)

    def test_stale_revision_does_not_produce_plan(self):
        with self.assertRaises(CliError):
            make_plan(self.manifest, self.revision, "mock/workspace", "sha256:" + "0" * 64)

    def test_initializer_refuses_nonempty_target_without_modification(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "workspace"
            target.mkdir()
            sentinel = target / "keep.txt"
            sentinel.write_text("preserve")
            with self.assertRaises(CliError):
                initialize_mock(self.manifest, self.revision, target)
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_initializer_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(CliError):
                initialize_mock(self.manifest, self.revision, link)
            self.assertEqual(list(real.iterdir()), [])

    def test_initializer_refuses_dangling_symlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            link = base / "link"
            link.symlink_to(base / "missing", target_is_directory=True)
            with self.assertRaises(CliError):
                initialize_mock(self.manifest, self.revision, link)


if __name__ == "__main__":
    unittest.main()


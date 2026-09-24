import json
import tempfile
import unittest
from pathlib import Path

from awr_cli.cli import CliError
from awr_cli.project_bootstrap import bootstrap


class ProjectBootstrapTests(unittest.TestCase):
    def test_preview_and_creation_are_revision_bound_and_local_only(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            preview = bootstrap("sample-project", "example-org", root / "product", root / "state", preview=True)
            self.assertEqual(preview["status"], "preview")
            result = bootstrap("sample-project", "example-org", root / "product", root / "state")
            self.assertEqual(result["status"], "created")
            manifest = json.loads((root / "product/agent-workflow-project.json").read_text())
            self.assertEqual(manifest["network"], "disabled")
            self.assertEqual(json.loads((root / "state/agent-workflow-state.json").read_text())["binding_digest"], result["binding_digest"])

    def test_rejects_nonempty_and_symlink_paths(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            product = root / "product"
            product.mkdir(); (product / "keep").write_text("user data")
            with self.assertRaisesRegex(CliError, "not_empty"):
                bootstrap("sample-project", "example-org", product, root / "state")
            target = root / "target"; target.mkdir()
            link = root / "link"; link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(CliError, "unsafe_project"):
                bootstrap("sample-project", "example-org", link, root / "state2")

    def test_rejects_invalid_identity_and_layout_collision_without_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with self.assertRaisesRegex(CliError, "invalid_project_identity"):
                bootstrap("Bad Name", "example-org", root / "p", root / "s")
            p, s = root / "p", root / "s"; p.mkdir(); s.mkdir()
            (p / "agent-workflow-project.json").write_text("sentinel")
            with self.assertRaisesRegex(CliError, "not_empty"):
                bootstrap("sample-project", "example-org", p, s)
            self.assertEqual((p / "agent-workflow-project.json").read_text(), "sentinel")

    def test_repeatability_requires_explicit_empty_or_new_targets(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            bootstrap("sample-project", "example-org", root / "p", root / "s")
            with self.assertRaisesRegex(CliError, "not_empty"):
                bootstrap("sample-project", "example-org", root / "p", root / "s")


if __name__ == "__main__":
    unittest.main()

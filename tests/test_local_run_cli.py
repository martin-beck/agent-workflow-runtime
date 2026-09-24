import contextlib
import io
import json
import unittest

from awr_cli.cli import main


class LocalRunCliTests(unittest.TestCase):
    def test_local_run_emits_reconciled_offline_trace(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["local-run", "--manifest", "project-manifest.yaml"]), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value["result"]["status"], "reconciled")
        self.assertEqual(value["result"]["network"], "disabled")


if __name__ == "__main__":
    unittest.main()

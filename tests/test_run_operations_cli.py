# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from awr_cli.cli import main
from scripts.run_operations import digest


class RunOperationsCliTests(unittest.TestCase):
    def invoke(self, *args: str) -> dict:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["run-ops", *args]), 0)
        return json.loads(output.getvalue())

    def test_cli_binds_run_and_exports_board_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "board.json"
            binding_path = root / "binding.json"
            binding_path.write_text(json.dumps({
                "run_id": "RUN-CLI-1", "task_id": "AR-0138", "task_revision": 3,
                "project": "agent-workflow-runtime", "worktree_key": "runtime-0138",
                "worktree_digest": digest("tree"), "graph_digest": digest("graph"), "owner": "WRK-CLI-1",
                "session_id": "SES-CLI-1", "lease_id": "LSE-CLI-1", "lease_fence": 1,
                "lease_expires_at": time.time() + 3600, "event_budget": 20, "accounting_budget": 50,
            }))
            started = self.invoke("start", "--state-file", str(state), "--binding", str(binding_path), "--operation-id", "OP-CLI-START")
            self.assertEqual(started["run_id"], "RUN-CLI-1")
            observation = root / "observation.json"
            observation.write_text(json.dumps({
                "runtime_state": "running", "coordinator_state": "running", "worker_id": "WRK-CLI-1",
                "session_id": "SES-CLI-1", "lease_id": "LSE-CLI-1", "lease_fence": 1,
                "checkpoint_digest": None, "authority_observations": {}, "failure_code": "",
            }))
            observed = self.invoke("observe", "--state-file", str(state), "--run-id", "RUN-CLI-1",
                "--operation-id", "OP-CLI-OBS", "--expected-revision", "1", "--lease-id", "LSE-CLI-1",
                "--lease-fence", "1", "--observation", str(observation), "--accounting-delta", "7")
            self.assertEqual((observed["status"], observed["accounting"]["consumed"]), ("running", 7))
            record = self.invoke("export-evidence", "--state-file", str(state), "--run-id", "RUN-CLI-1")
            self.assertEqual(record["binding"]["session_id"], "SES-CLI-1")
            self.assertEqual(record["accounting"]["remaining"], 43)


if __name__ == "__main__":
    unittest.main()

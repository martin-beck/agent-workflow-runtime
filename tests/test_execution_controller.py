import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from awr_cli.agent_registry import AdapterProfile, AdapterRegistry
from scripts.execution_controller import (
    ExecutionBinding,
    ExecutionController,
    ExecutionError,
)
from scripts.host_sandbox import SandboxBudget


class ExecutionControllerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.worktree = root / "worktree"
        self.worktree.mkdir()
        self.evidence = root / "evidence"
        self.registry = AdapterRegistry(root / "registry.json")
        self.registry.register(AdapterProfile("fake-exec", "1.0.0", ("deterministic-agent",), frozenset({"request", "close"}), ("start", "request", "close"), {"max_output_events": 4}, True))
        self.controller = ExecutionController(registry=self.registry, evidence_dir=self.evidence, clock=lambda: 100.0)
        self.binding = ExecutionBinding("AR-0131", 2, "agent-workflow-runtime", "sha256:" + "a" * 64, "agent-workflow-runtime-0131", "sha256:" + "b" * 64, "SES-AR0131-EXEC")
        self.lease = {"id": "LSE-AR0131-1", "worker": "WRK-AR0131-1", "fence": 1, "expires_at": 200.0}
        self.admission = {"status": "admitted", "task": "AR-0131", "task_revision": 2, "authority_state": "observed_only", "mandatory_order": ["coordinator", "awq", "awg", "ui"], "decision": "approved", "trace": [{"authority": name} for name in ("coordinator", "awq", "awg", "ui")]}

    def tearDown(self):
        self.directory.cleanup()

    def run_controller(self, **changes):
        values = {"binding": self.binding, "lease": self.lease, "authority_admission": self.admission, "worktree": self.worktree, "adapter_id": "fake-exec", "registry_revision": 1, "budget": SandboxBudget(timeout_seconds=2)}
        values.update(changes)
        return self.controller.run(**values)

    def test_real_fake_process_has_bindings_and_durable_spawn_terminal_evidence(self):
        result = self.run_controller()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stdout"], "AWR-FAKE-AGENT-OK\n")
        self.assertIn("AWR-FAKE-AGENT-ERR", result["stderr"])
        record = __import__("json").loads(Path(result["evidence"]).read_text())
        self.assertEqual(record["spawn"]["task_revision"], 2)
        self.assertEqual(record["spawn"]["stdio"], {"stdin": "pipe", "stdout": "pipe", "stderr": "pipe"})
        self.assertEqual(record["spawn"]["process_group"], "session-leader")
        self.assertEqual(record["terminal"]["status"], "completed")
        self.assertTrue(record["terminal"]["cleanup"])

    def test_missing_or_stale_binding_fails_before_sandbox_or_process(self):
        cases = []
        stale_lease = copy.deepcopy(self.lease); stale_lease["expires_at"] = 100.0; cases.append({"lease": stale_lease})
        missing_authority = copy.deepcopy(self.admission); missing_authority.pop("decision"); cases.append({"authority_admission": missing_authority})
        crossed = copy.deepcopy(self.binding); crossed = ExecutionBinding(crossed.task_id, 3, crossed.project_key, crossed.project_revision, crossed.worktree_key, crossed.worktree_digest, crossed.session_id); cases.append({"binding": crossed})
        for change in cases:
            with self.subTest(change=change), patch("scripts.execution_controller.HostSandbox") as sandbox:
                with self.assertRaises(ExecutionError):
                    self.run_controller(**change)
                sandbox.assert_not_called()

    def test_stale_registry_profile_and_replay_fail_closed(self):
        with self.assertRaises(ExecutionError):
            self.run_controller(registry_revision=2)
        with self.assertRaises(ExecutionError):
            self.run_controller(adapter_id="fake-sandbox")
        self.run_controller()
        with self.assertRaises(ExecutionError):
            self.run_controller()


if __name__ == "__main__":
    unittest.main()

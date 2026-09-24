from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from scripts.host_sandbox import (
    HostSandbox,
    SandboxBudget,
    SandboxCapabilities,
    SandboxError,
)


class HostSandboxTests(unittest.TestCase):
    def sandbox(self):
        directory = tempfile.TemporaryDirectory()
        return HostSandbox(Path(directory.name)), directory

    def test_capabilities_are_positive_and_success_isolated(self):
        sandbox, directory = self.sandbox()
        try:
            self.assertTrue(sandbox.capabilities.enforceable)
            result = sandbox.run(["/usr/bin/python3", "-c", "open('created','w').write('ok')"])
            self.assertEqual(result["status"], "ok")
            self.assertEqual((Path(directory.name) / "created").read_text(), "ok")
        finally:
            directory.cleanup()

    def test_network_and_filesystem_escape_are_denied(self):
        sandbox, directory = self.sandbox()
        try:
            script = "import socket; socket.create_connection(('127.0.0.1', 9), .1)"
            network = sandbox.run(["/usr/bin/python3", "-c", script])
            self.assertNotEqual(network["status"], "ok")
            write_etc = sandbox.run(["/usr/bin/python3", "-c", "open('/etc/awr-hostile','w').write('x')"])
            self.assertNotEqual(write_etc["status"], "ok")
            self.assertFalse(Path("/etc/awr-hostile").exists())
            (Path(directory.name) / "escape").symlink_to("/etc")
            symlink = sandbox.run(["/usr/bin/python3", "-c", "open('escape/awr-hostile','w').write('x')"])
            self.assertNotEqual(symlink["status"], "ok")
        finally:
            directory.cleanup()

    def test_resource_timeout_and_process_cleanup(self):
        sandbox, directory = self.sandbox()
        try:
            timeout = sandbox.run(["/usr/bin/python3", "-c", "import time; time.sleep(10)"], budget=SandboxBudget(timeout_seconds=.1))
            self.assertEqual(timeout["status"], "timeout")
            self.assertTrue(timeout["process_tree_clean"])
            disk = sandbox.run(["/usr/bin/python3", "-c", "open('large','wb').write(b'x'*100000)"], budget=SandboxBudget(disk_bytes=1024))
            self.assertNotEqual(disk["status"], "ok")
            memory = sandbox.run(["/usr/bin/python3", "-c", "bytearray(64*1024*1024)"], budget=SandboxBudget(memory_bytes=16*1024*1024))
            self.assertNotEqual(memory["status"], "ok")
            processes = sandbox.run(["/usr/bin/python3", "-c", "import os; [os.fork() for _ in range(32)]"], budget=SandboxBudget(process_count=2))
            self.assertNotEqual(processes["status"], "ok")
            handle = sandbox.launch(["/usr/bin/python3", "-c", "import time; time.sleep(10)"])
            time.sleep(.03)
            sandbox.cancel(handle)
            handle.communicate()
            self.assertIsNotNone(handle.poll())
        finally:
            directory.cleanup()

    def test_admission_fails_closed_when_probe_is_unavailable(self):
        with tempfile.TemporaryDirectory() as root, self.assertRaises(SandboxError):
            HostSandbox(Path(root), runtime="/does/not/exist")

    def test_reported_subprocess_capabilities_do_not_qualify(self):
        capabilities = SandboxCapabilities("subprocess", True, True, True, True, True, True, True, True, True)
        self.assertFalse(capabilities.enforceable)


if __name__ == "__main__":
    unittest.main()

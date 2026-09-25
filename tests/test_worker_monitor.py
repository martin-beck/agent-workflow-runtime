import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scripts.worker_monitor import MonitorPolicy, MonitorError, RecoveryStore, WorkerMonitor


class WorkerMonitorTests(unittest.TestCase):
    def monitor(self, **kwargs):
        return WorkerMonitor(policy=MonitorPolicy(.03, .12, .03), **kwargs)

    def test_heartbeats_progress_and_resource_observation(self):
        beats, checkpoints = [], []
        p = subprocess.Popen([sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(.10)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        result = self.monitor(heartbeat=lambda: beats.append(1), checkpoint=checkpoints.append).wait(p, timeout=1, output_limit=1024)
        self.assertGreaterEqual(len(beats), 1)
        self.assertTrue(checkpoints)
        self.assertTrue(result["progress_observed"])
        self.assertTrue(result["process_group_clean"])
        self.assertIn(b"ready", result["stdout"])
        self.assertIn("observed", result["resource_observation"])

    def test_hung_and_output_stalled_workers_are_killed(self):
        for code in ("import time; time.sleep(2)", "import os,time; os.write(1,b'x'); time.sleep(2)"):
            with self.subTest(code=code):
                p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                result = self.monitor().wait(p, timeout=.5, output_limit=1024)
                self.assertIn(result["status"], {"timed_out", "stalled"})
                self.assertTrue(result["process_group_clean"])

    def test_cancel_signal_race_kills_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp)/"descendant.pid"
            code = "import subprocess,sys,time; c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); open(sys.argv[1],'w').write(str(c.pid)); time.sleep(10)"
            p = subprocess.Popen([sys.executable, "-c", code, str(pidfile)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            deadline = time.monotonic()+2
            while not pidfile.exists() and time.monotonic()<deadline: time.sleep(.01)
            result = self.monitor(cancel_requested=lambda: True).wait(p, timeout=3, output_limit=1024)
            self.assertTrue(result["cancelled"])
            self.assertTrue(result["process_group_clean"])
            child = int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError): os.kill(child, 0)

    def test_checkpoint_restart_uses_new_fence_and_bounded_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RecoveryStore(Path(tmp)/"checkpoint.json", max_attempts=2)
            old = {"task_id":"AR-0134", "task_revision":2, "session_id":"SES-AR0134-1", "worktree_digest":"sha256:x", "worker_id":"WRK-A", "lease_id":"LSE-1", "lease_fence":1}
            store.checkpoint(old, {"output_bytes":12})
            newer = {**old, "worker_id":"WRK-B", "lease_id":"LSE-2", "lease_fence":2}
            recovered = store.recover(binding=newer, attempts=0, old_fence=1)
            self.assertTrue(recovered["resume"])
            with self.assertRaisesRegex(MonitorError, "retry_exhausted"):
                store.recover(binding={**newer, "lease_fence":3}, attempts=2, old_fence=2)
            with self.assertRaisesRegex(MonitorError, "recovery_fence_invalid"):
                store.recover(binding=old, attempts=0, old_fence=1)


if __name__ == "__main__":
    unittest.main()

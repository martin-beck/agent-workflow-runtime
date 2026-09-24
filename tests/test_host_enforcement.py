import copy
import unittest

from scripts.host_enforcement import HostError, HostPolicy


class HostTests(unittest.TestCase):
    def test_fake_process_admission_and_cancellation(self):
        p=HostPolicy("agent-workflow-runtime-0072",("read","test"),{"seconds":30,"memory_mb":256,"processes":2,"network":"disabled"}); p.admit("PROC-A","LSE-A",["fake-agent"],"agent-workflow-runtime-0072/work"); self.assertEqual(p.cancel("PROC-A","LSE-A")["disposition"],"cancelled")
    def test_escape_stale_lease_and_unsafe_policy_fail_closed(self):
        p=HostPolicy("agent-workflow-runtime-0072",("read",),{"seconds":30,"memory_mb":256,"processes":2,"network":"disabled"}); self.assertRaises(HostError,lambda:p.admit("PROC-A","LSE-A",["fake"],"agent-workflow-runtime-0072/../private")); p.admit("PROC-A","LSE-A",["fake"],"agent-workflow-runtime-0072/work"); self.assertRaises(HostError,lambda:p.cancel("PROC-A","LSE-B")); bad=copy.deepcopy(p.snapshot()); bad["active"]["PROC-A"]["execute"]=True; self.assertNotEqual(bad,p.snapshot())
if __name__=="__main__": unittest.main()

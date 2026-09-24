import unittest

from scripts.runtime_host_boundary import Boundary, BoundaryError


class BoundaryTests(unittest.TestCase):
    def test_local_fake_process_and_lease_bound_cancel(self):
        b=Boundary("agent-workflow-runtime-0072",["read","test"],{"seconds":30,"memory_mb":256,"processes":2,"network":"disabled"}); b.admit("PROC-A","LSE-A",["fake-agent"],"agent-workflow-runtime-0072/work"); self.assertEqual(b.cancel("PROC-A","LSE-A")["disposition"],"cancelled")
    def test_escape_and_stale_cancel_fail_closed(self):
        b=Boundary("agent-workflow-runtime-0072",["read"],{"seconds":30,"memory_mb":256,"processes":2,"network":"disabled"}); self.assertRaises(BoundaryError,lambda:b.admit("PROC-A","LSE-A",["fake"],"agent-workflow-runtime-0072/../private")); b.admit("PROC-A","LSE-A",["fake"],"agent-workflow-runtime-0072/work"); self.assertRaises(BoundaryError,lambda:b.cancel("PROC-A","LSE-B"))
if __name__=="__main__": unittest.main()

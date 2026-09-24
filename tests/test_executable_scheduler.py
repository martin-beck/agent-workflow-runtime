import unittest

from scripts.executable_scheduler import RuntimeScheduler, RuntimeSchedulerError


class SchedulerTests(unittest.TestCase):
    def test_dependency_order_and_terminal_completion(self):
        r=RuntimeScheduler(); r.submit("OP-A","JOB-A"); r.submit("OP-B","JOB-B",("JOB-A",)); first=r.dispatch("OP-D1","worker-a",0); self.assertEqual(first.job_id,"JOB-A"); r.complete("OP-C1","JOB-A","worker-a",first.lease_id,1); second=r.dispatch("OP-D2","worker-b",1); self.assertEqual(second.job_id,"JOB-B"); r.complete("OP-C2","JOB-B","worker-b",second.lease_id,2); self.assertEqual({j.state for j in r.scheduler.jobs.values()},{"succeeded"})
    def test_idempotency_and_stale_lease_fail_closed(self):
        r=RuntimeScheduler(); r.submit("OP-A","JOB-A"); lease=r.dispatch("OP-D","worker-a",0); self.assertEqual(r.dispatch("OP-D","worker-a",0),lease); self.assertRaises(RuntimeSchedulerError,lambda:r.complete("OP-C","JOB-A","worker-b",lease.lease_id,1))
if __name__=="__main__": unittest.main()

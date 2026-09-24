import unittest

from scripts.executable_observability import ObservabilityError, Observer


class ObservabilityTests(unittest.TestCase):
    def test_digest_only_metrics_and_alerts(self):
        o=Observer(); o.observe("job","JOB-A","submitted"); o.observe("job","JOB-A","failed",{"reason":"worker_lost"}); out=o.export(); self.assertEqual(out["counters"]["failed"],1); self.assertEqual(out["privacy"],"digest_only"); self.assertFalse(out["execute"])
    def test_private_and_budgeted_observations_fail_closed(self):
        o=Observer(1); o.observe("job","JOB-A","submitted"); self.assertRaises(ObservabilityError,lambda:o.observe("job","JOB-A","running")); self.assertRaises(ObservabilityError,lambda:Observer().observe("job","JOB-A","submitted",{"prompt":"secret"}))
if __name__=="__main__": unittest.main()

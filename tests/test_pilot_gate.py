import unittest

from scripts.pilot_gate import PilotError, evaluate


class PilotGateTests(unittest.TestCase):
    def test_pending_approval_is_blocked_without_execution(self):
        record={"revision":1,"cohort":["offline-reference"],"approvals":{"coordinator_lease":"pending","host_security":"pending","quality_gate":"approved","guidance_decision":"pending","ui_approval":"pending","accounting":"approved","rollback":"approved","incident_owner":"approved"},"offline_qualification":"sha256:"+"a"*64,"safety":{"max_jobs":1,"max_runtime_seconds":300,"rollback":"required","cutover":"human_gated"}}
        from scripts.pilot_gate import digest
        record["expected"]={"status":"blocked","execute":False,"live_provider":"not_performed","live_host":"not_performed","reason":"external approval incomplete","cohort_digest":digest(record["cohort"]),"offline_qualification":record["offline_qualification"]}
        self.assertEqual(evaluate(record)["status"],"blocked")
    def test_missing_approval_fails_closed(self):
        self.assertRaises(PilotError,evaluate,{"revision":1,"cohort":[],"approvals":{},"offline_qualification":"x","safety":{},"expected":{}})
if __name__=="__main__": unittest.main()

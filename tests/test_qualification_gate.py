import copy
import unittest

from scripts.qualification_gate import QualificationError, qualify, validate


class QualificationTests(unittest.TestCase):
    def test_reproducible_cross_agent_failure_and_accounting_gate(self):
        a=qualify([1,7,42]); self.assertEqual(a,qualify([1,7,42])); self.assertEqual(len(a["scenarios"]),3); self.assertTrue(a["accounting"]["reconciled"]); self.assertEqual(a["production_readiness"],"unverified")
    def test_bounds_and_tampering_fail_closed(self):
        self.assertRaises(QualificationError,lambda:qualify([])); self.assertRaises(QualificationError,lambda:qualify([1,1,7])); record={"seeds":[1,7,42],"agents":3,"expected":{"contract":"awr-rigorous-offline-qualification@1.0.0","seeds":[1,7,42],"agents":3,"scenario_count":3,"accounting_usage":{"seconds":6,"tokens":9,"events":3},"contractor_state":"accepted","evidence_class":"offline_deterministic","live_provider_support":"unverified","production_readiness":"unverified","execute":False}}; changed=copy.deepcopy(record); changed["expected"]["scenario_count"]=99; self.assertRaises(QualificationError,lambda:validate(changed))

if __name__ == "__main__": unittest.main()

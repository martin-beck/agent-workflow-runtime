import copy
import unittest

from scripts.executable_qualification import QualificationError, qualify, validate


class QualificationTests(unittest.TestCase):
    def test_reproducible_executable_gate(self):
        a=qualify([1,7,42]); self.assertEqual(a,qualify([1,7,42])); self.assertEqual([s["workflow_state"] for s in a["scenarios"]],["accepted"]*3); self.assertEqual(a["production_readiness"],"unverified")
    def test_wrong_seed_and_tampering_fail_closed(self):
        self.assertRaises(QualificationError,lambda:qualify([1,2,3])); record={"seeds":[1,7,42],"expected":{"contract":"awr-executable-runtime-qualification@1.0.0","seeds":[1,7,42],"scenario_count":3,"workflow_states":["failed"]*3,"evidence_class":"offline_executable","live_provider_support":"unverified","production_readiness":"unverified","execute":False}}; self.assertRaises(QualificationError,lambda:validate(copy.deepcopy(record)))
if __name__=="__main__": unittest.main()

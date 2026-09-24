import copy
import unittest

from scripts.durable_runtime_journal import Journal, RecoveryError


class JournalTests(unittest.TestCase):
    def test_crash_recovery_fence_and_digest_chain(self):
        j=Journal(); j.append("OP-AR0070-1","start",{"phase":"boot"}); checkpoint=j.checkpoint("CHK-AR0070-1")
        with self.assertRaises(RecoveryError): j.append("OP-AR0070-2","progress",{"phase":"work"},crash=True)
        self.assertRaises(RecoveryError,lambda:j.append("OP-AR0070-3","complete",{},1)); j.recover(checkpoint,2); j.append("OP-AR0070-3","complete",{},2); self.assertEqual(j.state,"terminal")
    def test_tamper_and_changed_replay_fail_closed(self):
        j=Journal(); j.append("OP-AR0070-1","start",{"phase":"boot"}); self.assertRaises(RecoveryError,lambda:j.append("OP-AR0070-1","start",{"phase":"changed"})); bad=copy.deepcopy(j.export()); bad["records"][0]["record_digest"]="sha256:"+"f"*64; self.assertRaises(RecoveryError,lambda:Journal(bad))
if __name__=="__main__": unittest.main()

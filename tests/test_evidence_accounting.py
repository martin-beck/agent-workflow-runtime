import unittest

from scripts.evidence_accounting import AccountingError, Ledger


class EvidenceTests(unittest.TestCase):
    def test_digest_chain_and_reconciliation(self):
        l=Ledger("JOB-A","LEASE-A",{"seconds":5,"tokens":10,"events":2}); l.append("EV-A","dispatch","local_measurement",{"seconds":1,"tokens":2}); l.append("EV-B","result","provider_reported",{"seconds":2,"tokens":3}); out=l.export(); self.assertTrue(out["reconciled"]); self.assertFalse(out["execute"]); self.assertNotEqual(out["events"][0]["digest"],out["events"][1]["digest"])
    def test_duplicate_budget_and_privacy_fail_closed(self):
        l=Ledger("JOB-A","LEASE-A",{"seconds":1,"tokens":1,"events":1}); l.append("EV-A","dispatch","supplied_estimate",{"seconds":1,"tokens":1})
        for fn in (lambda: l.append("EV-A","result","local_measurement",{"seconds":0,"tokens":0}), lambda: l.append("EV-B","result","local_measurement",{"seconds":1,"tokens":0})): self.assertRaises(AccountingError,fn)
        self.assertRaises(AccountingError, lambda: Ledger("JOB-A","LEASE-A",{"seconds":1,"tokens":1,"events":1}).append("EV-A","result","secret-token",{"seconds":0,"tokens":0}))
if __name__=="__main__": unittest.main()

#!/usr/bin/env python3
"""Digest-linked evidence and offline usage accounting for AR-0065."""
import hashlib
import json
import re

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output", re.IGNORECASE)
class AccountingError(ValueError): pass
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def digest(value): return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()
def safe(value):
    if isinstance(value, dict): return all((str(k) == "tokens" or not PRIVATE.search(str(k))) and safe(v) for k,v in value.items())
    if isinstance(value, list): return all(safe(v) for v in value)
    return not (isinstance(value, str) and (len(value)>256 or PRIVATE.search(value)))

class Ledger:
    def __init__(self, job_id, lease_id, budget):
        if not re.fullmatch(r"JOB-[A-Z0-9-]{1,40}", job_id) or not re.fullmatch(r"LEASE-[A-Z0-9-]{1,40}", lease_id) or set(budget) != {"seconds","tokens","events"}: raise AccountingError("invalid binding or budget")
        self.job_id=job_id; self.lease_id=lease_id; self.budget=dict(budget); self.events=[]; self.usage={"seconds":0,"tokens":0,"events":0}
    def append(self, event_id, kind, source, usage):
        if not re.fullmatch(r"EV-[A-Z0-9-]{1,40}", event_id) or any(e["event_id"]==event_id for e in self.events): raise AccountingError("duplicate event")
        if not isinstance(usage,dict) or set(usage)!={"seconds","tokens"} or any(not isinstance(v,int) or v<0 for v in usage.values()): raise AccountingError("invalid usage")
        next_usage={k:self.usage[k]+usage[k] for k in usage}; next_usage["events"]=len(self.events)+1
        if any(next_usage[k]>self.budget[k] for k in self.budget): raise AccountingError("budget exceeded")
        body={"event_id":event_id,"sequence":len(self.events)+1,"job_id":self.job_id,"lease_id":self.lease_id,"kind":kind,"source":source,"usage":usage,"previous_digest":self.events[-1]["digest"] if self.events else "sha256:"+"0"*64}
        if not safe(body): raise AccountingError("privacy violation")
        body["digest"]=digest(body); self.events.append(body); self.usage=next_usage; return body
    def export(self):
        return {"job_id":self.job_id,"lease_id":self.lease_id,"events":self.events,"usage":self.usage,"budget":self.budget,"reconciled":self.usage=={**self.usage,"events":len(self.events)},"execute":False,"billing":"unverified"}

def validate(record):
    if not isinstance(record,dict) or set(record)!={"job_id","lease_id","budget","input_events","expected"} or not safe(record): raise AccountingError("unknown, missing, or privacy-bearing field")
    ledger=Ledger(record["job_id"],record["lease_id"],record["budget"])
    for item in record["input_events"]: ledger.append(item["event_id"],item["kind"],item["source"],item["usage"])
    actual=ledger.export()
    if actual != record["expected"]: raise AccountingError("accounting reconciliation mismatch")
    return {"contract":"awr-evidence-accounting@1.0.0","events":len(ledger.events),"usage":ledger.usage,"reconciled":True,"billing":"unverified","execute":False}

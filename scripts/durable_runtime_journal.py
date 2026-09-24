#!/usr/bin/env python3
"""Restart/recovery journal layered over the AR-0069 local kernel."""
import copy
import hashlib
import json
import re

GENESIS="sha256:"+"0"*64
class RecoveryError(ValueError): pass
def digest(v): return "sha256:"+hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
class Journal:
    def __init__(self, snapshot=None):
        self.records=[]; self.fence=1; self.state="active"; self.pending=None
        if snapshot is not None: self.restore(snapshot)
    def append(self, operation_id, event, payload=None, fence=1, crash=False):
        if self.state in {"ambiguous","blocked"} or fence != self.fence or not re.fullmatch(r"OP-[A-Z0-9-]{1,48}",operation_id) or event not in {"start","progress","checkpoint","complete","cancel"} or not isinstance(payload or {},dict): raise RecoveryError("stale, blocked, or malformed append")
        if any(r["operation_id"]==operation_id for r in self.records):
            prior=next(r for r in self.records if r["operation_id"]==operation_id)
            if prior["event"] != event or prior["payload"] != (payload or {}): raise RecoveryError("changed replay")
            return {"disposition":"replayed","digest":prior["record_digest"]}
        body={"sequence":len(self.records)+1,"operation_id":operation_id,"event":event,"payload":copy.deepcopy(payload or {}),"fence":fence,"previous_digest":self.records[-1]["record_digest"] if self.records else GENESIS}
        body["record_digest"]=digest(body)
        if crash: self.pending=body; self.state="ambiguous"; raise RecoveryError("ambiguous write")
        self.records.append(body)
        if event in {"complete","cancel"}: self.state="terminal"
        return {"disposition":"committed","digest":body["record_digest"]}
    def checkpoint(self, checkpoint_id):
        if self.state not in {"active","terminal"} or not re.fullmatch(r"CHK-[A-Z0-9-]{1,48}",checkpoint_id): raise RecoveryError("invalid checkpoint")
        return {"checkpoint_id":checkpoint_id,"head_digest":self.records[-1]["record_digest"] if self.records else GENESIS,"fence":self.fence}
    def recover(self, checkpoint, fence):
        if self.state != "ambiguous" or fence <= self.fence or checkpoint["head_digest"] != (self.records[-1]["record_digest"] if self.records else GENESIS): raise RecoveryError("invalid recovery fence or checkpoint")
        self.fence=fence; self.pending=None; self.state="active"; return {"disposition":"recovered","fence":fence}
    def export(self): return {"records":copy.deepcopy(self.records),"fence":self.fence,"state":self.state}
    def restore(self, snapshot):
        if not isinstance(snapshot,dict) or set(snapshot)!={"records","fence","state"}: raise RecoveryError("invalid journal snapshot")
        previous=GENESIS
        for n,record in enumerate(snapshot["records"],1):
            if record.get("sequence")!=n or record.get("previous_digest")!=previous or record.get("record_digest")!=digest({k:v for k,v in record.items() if k!="record_digest"}): raise RecoveryError("broken journal chain")
            previous=record["record_digest"]
        if not isinstance(snapshot["fence"],int) or snapshot["fence"]<1 or snapshot["state"] not in {"active","terminal","ambiguous","blocked"}: raise RecoveryError("invalid journal state")
        self.records=copy.deepcopy(snapshot["records"]); self.fence=snapshot["fence"]; self.state=snapshot["state"]

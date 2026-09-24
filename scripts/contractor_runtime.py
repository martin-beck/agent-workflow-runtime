#!/usr/bin/env python3
"""Offline composition of scheduler, adapter, evidence, and contractor contracts."""
import hashlib
import json
from typing import ClassVar


class WorkflowError(ValueError): pass
def digest(v): return "sha256:"+hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
class LocalContractorRuntime:
    STATES=("submitted","scheduled","assigned","executing","observed","quality_pending","oracle_pending","human_pending","accepted","rejected")
    NEXT: ClassVar = {"submitted":{"scheduled"},"scheduled":{"assigned"},"assigned":{"executing"},"executing":{"observed"},"observed":{"quality_pending"},"quality_pending":{"oracle_pending","rejected"},"oracle_pending":{"human_pending"},"human_pending":{"accepted"}}
    def __init__(self): self.state="submitted"; self.events=[]; self.attempt=0
    def _move(self,state,authority):
        if state not in self.STATES or self.state in {"accepted","rejected"} or state not in self.NEXT.get(self.state,set()): raise WorkflowError("invalid terminal transition")
        self.events.append({"sequence":len(self.events)+1,"from":self.state,"to":state,"authority":authority,"evidence_digest":digest({"from":self.state,"to":state,"sequence":len(self.events)+1})}); self.state=state
    def run_success(self):
        for state,authority in (("scheduled","scheduler"),("assigned","scheduler"),("executing","runtime"),("observed","runtime"),("quality_pending","quality"),("oracle_pending","guidance"),("human_pending","ui"),("accepted","coordinator")): self._move(state,authority)
        return self.result()
    def reject_and_revise(self):
        if self.state!="quality_pending": raise WorkflowError("revision requires quality pending")
        self._move("rejected","quality"); self.attempt+=1; self.state="submitted"; self._move("scheduled","scheduler"); return self.result()
    def result(self): return {"state":self.state,"attempt":self.attempt,"events":self.events,"execute":False,"quality":"accepted" if self.state=="accepted" else "not_decided","remote":"unverified"}

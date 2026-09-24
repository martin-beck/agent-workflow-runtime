#!/usr/bin/env python3
"""Bounded, authority-preserving closed-loop contractor model for AR-0066."""
import hashlib
import json
import re

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
class ContractorError(ValueError): pass
STEPS = {"intake":"clarification", "clarification":"planning", "planning":"admitted", "admitted":"assigned", "assigned":"executing", "executing":"observed", "observed":"quality_pending", "quality_pending":"oracle_pending", "oracle_pending":"human_pending", "human_pending":"artifact_handoff", "artifact_handoff":"accepted"}

def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def digest(value): return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

class Contractor:
    def __init__(self, task_revision=1, max_revisions=2):
        if task_revision < 1 or max_revisions < 0: raise ContractorError("invalid bounds")
        self.revision=task_revision; self.max_revisions=max_revisions; self.state="intake"; self.attempt=0; self.events=[]
    def transition(self, target, authority="runtime", evidence=None):
        if self.state in {"accepted","rejected"} or STEPS.get(self.state) != target: raise ContractorError("invalid lifecycle transition")
        if target in {"oracle_pending","human_pending"} and authority == "runtime": raise ContractorError("authority substitution")
        evidence = evidence or {"state":target,"revision":self.revision}
        item={"sequence":len(self.events)+1,"from":self.state,"to":target,"authority":authority,"task_revision":self.revision,"evidence_digest":digest(evidence)}
        self.events.append(item); self.state=target; return item
    def reject(self, reason="quality_failed"):
        if self.state not in {"quality_pending","oracle_pending","human_pending"} or not reason: raise ContractorError("invalid rejection")
        self.events.append({"sequence":len(self.events)+1,"from":self.state,"to":"rejected","authority":"quality","task_revision":self.revision,"evidence_digest":digest({"reason":reason})}); self.state="rejected"
    def revise(self):
        if self.state != "rejected" or self.attempt >= self.max_revisions: raise ContractorError("revision bound exceeded")
        self.attempt += 1; self.revision += 1; self.state="planning"
        self.events.append({"sequence":len(self.events)+1,"from":"rejected","to":"planning","authority":"coordinator","task_revision":self.revision,"evidence_digest":digest({"attempt":self.attempt,"revision":self.revision})})
    def happy_path(self):
        for target, authority in (("clarification","runtime"),("planning","runtime"),("admitted","coordinator"),("assigned","coordinator"),("executing","runtime"),("observed","runtime"),("quality_pending","quality"),("oracle_pending","guidance"),("human_pending","ui"),("artifact_handoff","runtime"),("accepted","coordinator")): self.transition(target,authority)
        return self.result()
    def result(self):
        return {"state":self.state,"task_revision":self.revision,"attempt":self.attempt,"events":self.events,"execute":False,"quality":"not_decided" if self.state not in {"accepted","rejected"} else ("accepted" if self.state=="accepted" else "rejected"),"human_gate":"not_decided"}

def validate(record):
    if set(record) != {"task_revision","max_revisions","expected"}: raise ContractorError("unknown or missing field")
    c=Contractor(record["task_revision"],record["max_revisions"]); actual=c.happy_path()
    if actual != record["expected"]: raise ContractorError("closed-loop trace mismatch")
    return {"contract":"awr-closed-loop-contractor@1.0.0","state":actual["state"],"events":len(actual["events"]),"execute":False,"quality":"accepted"}

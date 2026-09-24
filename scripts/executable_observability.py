#!/usr/bin/env python3
"""Privacy-safe operational observability model for AR-0078."""
import hashlib
import json
import re


class ObservabilityError(ValueError): pass
PRIVATE=re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output|host.?identifier",re.IGNORECASE)
def digest(v): return "sha256:"+hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
class Observer:
    def __init__(self,max_events=64):
        if max_events<1: raise ObservabilityError("invalid event budget")
        self.max_events=max_events; self.events=[]; self.counters={"submitted":0,"running":0,"succeeded":0,"failed":0,"blocked":0}
    def observe(self,kind,job_id,status,metadata=None):
        if kind not in {"job","lease","adapter","accounting","incident"} or not re.fullmatch(r"JOB-[A-Z0-9-]{1,48}",job_id) or status not in self.counters or not isinstance(metadata or {},dict) or any(PRIVATE.search(str(k)) or PRIVATE.search(str(v)) for k,v in (metadata or {}).items()): raise ObservabilityError("unsafe observation")
        if len(self.events)>=self.max_events: raise ObservabilityError("observation budget exceeded")
        item={"sequence":len(self.events)+1,"kind":kind,"job_digest":digest(job_id),"status":status,"metadata":metadata or {},"evidence_digest":digest({"kind":kind,"job_id":job_id,"status":status,"metadata":metadata or {}})}; self.events.append(item); self.counters[status]+=1; return item
    def export(self): return {"events":self.events,"counters":self.counters,"alerts":["failed" for _ in range(self.counters["failed"])],"execute":False,"privacy":"digest_only","remote":"unverified"}

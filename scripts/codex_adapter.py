#!/usr/bin/env python3
"""Offline Codex-compatible adapter over AR-0073 transport."""
import hashlib
import json
import re


class AdapterError(ValueError): pass
def digest(v): return "sha256:"+hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
class CodexAdapter:
    provider="codex-compatible"
    capabilities=("request","stream","interrupt","checkpoint","resume")
    def __init__(self): self.state="new"; self.events=[]; self.binding=None
    def admit(self,session_id,lease_id):
        if self.state!="new" or not re.fullmatch(r"SES-[A-Z0-9-]{1,48}",session_id) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,48}",lease_id): raise AdapterError("invalid admission")
        self.binding={"session_id":session_id,"lease_id":lease_id}; self.state="admitted"; return self._event("admitted",{})
    def request(self,request_digest):
        if self.state!="admitted" or not re.fullmatch(r"sha256:[0-9a-f]{64}",request_digest): raise AdapterError("invalid request")
        self.state="active"; return self._event("request",{"request_digest":request_digest})
    def interrupt(self):
        if self.state!="active": raise AdapterError("invalid interruption")
        self.state="interrupted"; return self._event("interrupt",{})
    def close(self):
        if self.state not in {"admitted","active","interrupted"}: raise AdapterError("invalid close")
        self.state="closed"; return self._event("close",{})
    def _event(self,kind,payload):
        item={"sequence":len(self.events)+1,"provider":self.provider,"kind":kind,"payload_digest":digest(payload),"state":self.state,"execute":False}; self.events.append(item); return item
    def export(self): return {"provider":self.provider,"capabilities":list(self.capabilities),"state":self.state,"events":self.events,"execute":False,"network":"disabled"}

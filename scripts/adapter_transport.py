#!/usr/bin/env python3
"""Bounded normalized adapter transport model for AR-0073."""
import hashlib
import json
import re


class TransportError(ValueError): pass
def digest(value): return "sha256:"+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
class Transport:
    def __init__(self, task_revision=1, max_events=16, max_bytes=4096):
        if task_revision != 1 or max_events < 1 or max_bytes < 128: raise TransportError("invalid transport limits")
        self.binding=None; self.events=[]; self.max_events=max_events; self.max_bytes=max_bytes; self.state="new"
    def admit(self, session_id, worktree, lease_id, capabilities):
        if self.state != "new" or not re.fullmatch(r"SES-[A-Z0-9-]{1,48}",session_id) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,48}",lease_id) or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}",worktree) or not capabilities: raise TransportError("invalid transport binding")
        self.binding={"session_id":session_id,"worktree":worktree,"lease_id":lease_id,"capabilities":tuple(capabilities)}; self.state="admitted"; return self._event("admitted",{})
    def receive(self, event, payload):
        if self.state not in {"admitted","running","interrupted"} or event not in {"start","chunk","end","interrupt","checkpoint","close","failure"} or not isinstance(payload,dict) or any("secret" in str(k).lower() or "token" in str(k).lower() for k in payload): raise TransportError("invalid or private frame")
        if event in {"start","chunk"} and "request_digest" not in payload: raise TransportError("missing opaque request digest")
        if len(self.events) >= self.max_events or len(json.dumps(payload)) > self.max_bytes: raise TransportError("transport budget exceeded")
        if event=="start": self.state="running"
        elif event=="interrupt": self.state="interrupted"
        elif event=="close": self.state="closed"
        elif event=="failure": self.state="failed"
        return self._event(event,payload)
    def _event(self,event,payload):
        item={"sequence":len(self.events)+1,"event":event,"payload_digest":digest(payload),"state":self.state,"execute":False}; self.events.append(item); return item
    def export(self): return {"binding":self.binding,"events":self.events,"state":self.state,"execute":False,"network":"disabled"}

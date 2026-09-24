#!/usr/bin/env python3
"""AR-0072 additive host-policy model; preserves the AR-0031 implementation."""
import hashlib
import json
import re


class BoundaryError(ValueError): pass
def digest(value): return "sha256:" + hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
class Boundary:
    def __init__(self, worktree, capabilities, limits):
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}",worktree) or not capabilities or not set(capabilities)<= {"read","edit","test"}: raise BoundaryError("invalid capability boundary")
        if set(limits)!={"seconds","memory_mb","processes","network"} or any(not isinstance(limits[k],int) or limits[k]<=0 for k in ("seconds","memory_mb","processes")) or limits["network"] not in {"disabled","allowlisted"}: raise BoundaryError("unsafe resource boundary")
        self.worktree=worktree; self.capabilities=list(capabilities); self.limits=dict(limits); self.active={}
    def admit(self, process_id, lease_id, command, path):
        if not re.fullmatch(r"PROC-[A-Z0-9-]{1,48}",process_id) or not re.fullmatch(r"LSE-[A-Z0-9-]{1,48}",lease_id) or process_id in self.active or not command or any(not isinstance(x,str) or len(x)>128 for x in command) or not path.startswith(self.worktree+"/") or ".." in path.split("/"): raise BoundaryError("process admission rejected")
        self.active[process_id]={"process_id":process_id,"lease_id":lease_id,"command_digest":digest(command),"path_digest":digest(path),"execute":False}; return self.active[process_id]
    def cancel(self, process_id, lease_id):
        if process_id not in self.active or self.active[process_id]["lease_id"] != lease_id: raise BoundaryError("stale cancellation")
        self.active.pop(process_id); return {"process_id":process_id,"disposition":"cancelled","execute":False}
    def snapshot(self): return {"worktree":self.worktree,"capabilities":self.capabilities,"limits":self.limits,"active":self.active,"execute":False,"network":self.limits["network"]}

#!/usr/bin/env python3
"""Executable offline runtime kernel and local durable state boundary (AR-0069)."""
import copy
import hashlib
import json
import re

GENESIS = "sha256:" + "0" * 64
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output", re.IGNORECASE)

class KernelError(ValueError): pass
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def digest(value): return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()
def safe(value):
    if isinstance(value, dict): return all((str(k) == "tokens" or not PRIVATE.search(str(k))) and safe(v) for k, v in value.items())
    if isinstance(value, list): return all(safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))

class LocalStore:
    """Transactional local store; persistence is represented by export/import."""
    def __init__(self, snapshot=None):
        self.events=[]; self.operations={}; self.usage={"events":0,"seconds":0,"tokens":0}
        if snapshot is not None: self.restore(snapshot)
    def append(self, request, usage):
        if not safe(request) or not safe(usage): raise KernelError("privacy violation")
        op=request.get("operation_id")
        if not isinstance(op,str) or not re.fullmatch(r"OP-[A-Z0-9-]{1,48}",op): raise KernelError("invalid operation")
        if op in self.operations:
            if self.operations[op]["request"] != request: raise KernelError("changed replay")
            return copy.deepcopy(self.operations[op]["result"])
        if set(usage) != {"seconds","tokens"} or any(not isinstance(v,int) or v < 0 for v in usage.values()): raise KernelError("invalid usage")
        body={"sequence":len(self.events)+1,"request":copy.deepcopy(request),"usage":dict(usage),"previous_digest":self.events[-1]["event_digest"] if self.events else GENESIS}
        body["event_digest"]=digest(body)
        result={"disposition":"committed","sequence":body["sequence"],"event_digest":body["event_digest"]}
        self.events.append(body); self.operations[op]={"request":copy.deepcopy(request),"result":copy.deepcopy(result)}
        self.usage["events"] += 1; self.usage["seconds"] += usage["seconds"]; self.usage["tokens"] += usage["tokens"]
        return result
    def export(self): return {"events":copy.deepcopy(self.events),"operations":copy.deepcopy(self.operations),"usage":dict(self.usage)}
    def restore(self, snapshot):
        if not isinstance(snapshot,dict) or set(snapshot)!={"events","operations","usage"} or not safe(snapshot): raise KernelError("invalid snapshot")
        previous=GENESIS
        for number,event in enumerate(snapshot["events"],1):
            if event.get("sequence") != number or event.get("previous_digest") != previous or event.get("event_digest") != digest({k:v for k,v in event.items() if k != "event_digest"}): raise KernelError("broken journal")
            previous=event["event_digest"]
        if snapshot["usage"] != {"events":len(snapshot["events"]),"seconds":sum(e["usage"]["seconds"] for e in snapshot["events"]),"tokens":sum(e["usage"]["tokens"] for e in snapshot["events"])}: raise KernelError("usage mismatch")
        self.events=copy.deepcopy(snapshot["events"]); self.operations=copy.deepcopy(snapshot["operations"]); self.usage=dict(snapshot["usage"])

class RuntimeKernel:
    def __init__(self, task_revision=1, project="agent-workflow-runtime", worktree="agent-workflow-runtime-0069", store=None):
        if task_revision != 1 or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}",project) or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}",worktree): raise KernelError("invalid binding")
        self.binding={"task":{"id":"AR-0069","revision":1},"project":project,"worktree":worktree}; self.store=store or LocalStore(); self.state="ready"
    def record(self, operation_id, event, lease_id="LSE-AR0069-1", usage=None, payload=None):
        if self.state == "blocked" or not re.fullmatch(r"LSE-[A-Z0-9-]{1,48}",lease_id) or event not in {"admit","dispatch","observe","complete","reject"}: raise KernelError("invalid kernel transition")
        request={**self.binding,"operation_id":operation_id,"event":event,"lease_id":lease_id,"payload":payload or {}}
        result=self.store.append(request,usage or {"seconds":0,"tokens":0})
        if event in {"complete","reject"}: self.state="terminal"
        return result
    def snapshot(self): return {"binding":self.binding,"state":self.state,"store":self.store.export(),"execute":False,"network":"disabled","provider":"not_performed","llm":"not_performed"}
    @classmethod
    def recover(cls, snapshot):
        if not isinstance(snapshot,dict) or snapshot.get("execute") is not False: raise KernelError("unsafe recovery snapshot")
        kernel=cls(store=LocalStore(snapshot["store"])); kernel.state=snapshot["state"]
        if snapshot["binding"] != kernel.binding: raise KernelError("binding mismatch")
        return kernel

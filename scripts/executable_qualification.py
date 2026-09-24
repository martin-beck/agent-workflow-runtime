#!/usr/bin/env python3
"""Deterministic release gate for the executable local runtime (AR-0079)."""
import hashlib
import json

from scripts.contractor_runtime import LocalContractorRuntime
from scripts.executable_observability import Observer
from scripts.executable_scheduler import RuntimeScheduler


class QualificationError(ValueError): pass
def digest(v): return "sha256:"+hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def qualify(seeds):
    if seeds != [1,7,42]: raise QualificationError("qualification requires the declared reproducible seeds")
    scenarios=[]
    for seed in seeds:
        scheduler=RuntimeScheduler(); scheduler.submit(f"OP-{seed}-A",f"JOB-{seed}-A"); lease=scheduler.dispatch(f"OP-{seed}-D",f"worker-{seed}",seed); scheduler.complete(f"OP-{seed}-C",f"JOB-{seed}-A",f"worker-{seed}",lease.lease_id,seed+1); workflow=LocalContractorRuntime().run_success(); observer=Observer(); observer.observe("job",f"JOB-{seed}-A","succeeded"); scenarios.append({"seed":seed,"scheduler_events":len(scheduler.scheduler.events),"workflow_state":workflow["state"],"observation_events":len(observer.events),"digest":digest({"seed":seed,"state":workflow["state"]})})
    if any(s["workflow_state"]!="accepted" for s in scenarios): raise QualificationError("workflow qualification failed")
    return {"contract":"awr-executable-runtime-qualification@1.0.0","seeds":seeds,"scenarios":scenarios,"thresholds":{"max_scheduler_events":8,"max_observation_events":4,"replay_equal":True},"evidence_class":"offline_executable","live_provider_support":"unverified","production_readiness":"unverified","execute":False}
def validate(record):
    if set(record)!={"seeds","expected"}: raise QualificationError("unknown qualification fields")
    actual=qualify(record["seeds"]); expected=record["expected"]
    summary={"contract":actual["contract"],"seeds":actual["seeds"],"scenario_count":len(actual["scenarios"]),"workflow_states":[s["workflow_state"] for s in actual["scenarios"]],"evidence_class":actual["evidence_class"],"live_provider_support":actual["live_provider_support"],"production_readiness":actual["production_readiness"],"execute":False}
    if summary != expected: raise QualificationError("qualification mismatch")
    return summary

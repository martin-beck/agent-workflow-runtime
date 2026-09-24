#!/usr/bin/env python3
"""Deterministic offline qualification gate for the runtime contract stack."""
import hashlib
import json

from scripts.contractor_loop import Contractor
from scripts.evidence_accounting import Ledger
from scripts.fake_agent_simulator import FakeAgent, Simulator


class QualificationError(ValueError): pass
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def digest(value): return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def qualify(seeds, agents=3):
    if not seeds or len(seeds) > 16 or len(set(seeds)) != len(seeds) or agents not in {2, 3, 4}:
        raise QualificationError("invalid bounded qualification input")
    scenarios=[]
    for seed in seeds:
        fake=(FakeAgent("agent-alpha"), FakeAgent("agent-beta", failure="provider"), FakeAgent("agent-gamma", failure="host_loss"))[:agents]
        success=Simulator(fake, seed).run((0,)); failure=Simulator(fake, seed).run((1,)); expiry=Simulator(fake, seed).run((0,), lease_expiry=True)
        if success["state"] != "succeeded" or failure["state"] != "failed" or expiry["state"] != "queued": raise QualificationError("scenario invariant failed")
        scenarios.append({"seed":seed,"success_digest":digest(success),"failure_digest":digest(failure),"expiry_digest":digest(expiry)})
    ledger=Ledger("JOB-QUALIFICATION","LEASE-QUALIFICATION",{"seconds":len(seeds)*10,"tokens":len(seeds)*20,"events":len(seeds)*3})
    for index, seed in enumerate(seeds, 1): ledger.append(f"EV-QUAL-{index}","scenario","local_measurement",{"seconds":2,"tokens":3})
    loop=Contractor().happy_path()
    if loop["state"] != "accepted" or len(loop["events"]) != 11: raise QualificationError("contractor invariant failed")
    return {"contract":"awr-rigorous-offline-qualification@1.0.0","seeds":list(seeds),"agents":agents,"scenarios":scenarios,"accounting":ledger.export(),"contractor":loop,"thresholds":{"max_events":64,"max_revisions":2,"replay_equal":True},"evidence_class":"offline_deterministic","live_provider_support":"unverified","production_readiness":"unverified","execute":False}

def validate(record):
    if set(record) != {"seeds","agents","expected"}: raise QualificationError("unknown or missing qualification field")
    actual=qualify(record["seeds"],record["agents"])
    expected = record["expected"]
    summary = {"contract": actual["contract"], "seeds": actual["seeds"], "agents": actual["agents"], "scenario_count": len(actual["scenarios"]), "accounting_usage": actual["accounting"]["usage"], "contractor_state": actual["contractor"]["state"], "evidence_class": actual["evidence_class"], "live_provider_support": actual["live_provider_support"], "production_readiness": actual["production_readiness"], "execute": actual["execute"]}
    if expected != summary: raise QualificationError("qualification result mismatch")
    return {"contract": actual["contract"], "scenarios": len(actual["scenarios"]), "evidence_class": actual["evidence_class"], "live_provider_support": actual["live_provider_support"], "production_readiness": actual["production_readiness"], "execute": False}

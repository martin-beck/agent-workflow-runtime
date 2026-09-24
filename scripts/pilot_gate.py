#!/usr/bin/env python3
"""Fail-closed preparation gate for the separately approved live pilot."""
import hashlib
import json


class PilotError(ValueError): pass
def digest(value): return "sha256:" + hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",", ":")).encode()).hexdigest()

REQUIRED = ("coordinator_lease", "host_security", "quality_gate", "guidance_decision", "ui_approval", "accounting", "rollback", "incident_owner")
def evaluate(record):
    if set(record) != {"revision", "cohort", "approvals", "offline_qualification", "safety", "expected"}: raise PilotError("unknown or missing pilot field")
    if record["revision"] != 1 or not isinstance(record["cohort"], list) or not record["cohort"] or len(record["cohort"]) > 8: raise PilotError("invalid bounded cohort")
    if set(record["approvals"]) != set(REQUIRED): raise PilotError("approval set incomplete")
    if any(record["approvals"][key] != "approved" for key in REQUIRED):
        actual={"status":"blocked","execute":False,"live_provider":"not_performed","live_host":"not_performed","reason":"external approval incomplete","cohort_digest":digest(record["cohort"]),"offline_qualification":record["offline_qualification"]}
    else:
        if record["safety"] != {"max_jobs":1,"max_runtime_seconds":300,"rollback":"required","cutover":"human_gated"}: raise PilotError("unsafe pilot limits")
        actual={"status":"ready_for_separately_approved_pilot","execute":False,"live_provider":"not_performed","live_host":"not_performed","reason":"live execution requires separate approved action","cohort_digest":digest(record["cohort"]),"offline_qualification":record["offline_qualification"]}
    if record["expected"] != actual: raise PilotError("pilot gate result mismatch")
    return actual

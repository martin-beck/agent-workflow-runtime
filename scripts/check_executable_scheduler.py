#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0071."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.executable_scheduler import RuntimeScheduler, RuntimeSchedulerError


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); f=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision != 1 or set(spec)!={"schema_version","specification_id","version","task","offline","invariants"} or spec["task"]!={"id":"AR-0071","revision":1} or spec["offline"]["execute"] is not False: raise RuntimeSchedulerError("unsafe specification")
        runtime=RuntimeScheduler(); leases={}
        for action in f["actions"]:
            if action["kind"]=="submit": runtime.submit(action["operation_id"],action["job_id"],action.get("dependencies",()),action.get("priority",50))
            elif action["kind"]=="dispatch": leases[action["job_id"]]=runtime.dispatch(action["operation_id"],action["worker_id"],action["now"])
            elif action["kind"]=="complete": runtime.complete(action["operation_id"],action["job_id"],action["worker_id"],leases[action["job_id"]].lease_id,action["now"])
            else: raise RuntimeSchedulerError("unknown action")
        result=runtime.snapshot(); expected=f["expected"]
        if {"states":{key:value["state"] for key,value in result["jobs"].items()},"events":len(result["events"]),"execute":False} != expected: raise RuntimeSchedulerError("scheduler fixture mismatch")
        print(json.dumps({"contract":"awr-executable-scheduler@1.0.0","jobs":len(result["jobs"]),"events":len(result["events"]),"execute":False},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,RuntimeSchedulerError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

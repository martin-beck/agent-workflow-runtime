#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0072 host enforcement."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.host_enforcement import HostError, HostPolicy


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); fixture=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision!=1 or set(spec)!={"schema_version","specification_id","version","task","offline","invariants"} or spec["task"]!={"id":"AR-0072","revision":1} or spec["offline"]["execute"] is not False: raise HostError("unsupported or unsafe specification")
        policy=HostPolicy(fixture["worktree"],fixture["capabilities"],fixture["limits"])
        for action in fixture["actions"]:
            if action["kind"]=="admit": policy.admit(action["process_id"],action["lease_id"],action["command"],action["path"])
            elif action["kind"]=="cancel": policy.cancel(action["process_id"],action["lease_id"])
            else: raise HostError("unknown action")
        if policy.snapshot()!=fixture["expected"]: raise HostError("host fixture mismatch")
        print(json.dumps({"contract":"awr-host-enforcement@1.0.0","active":len(policy.active),"execute":False,"network":policy.snapshot()["network"]},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,HostError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

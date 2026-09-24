#!/usr/bin/env python3
"""Fail-closed checker for the additive AR-0072 host boundary."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.runtime_host_boundary import Boundary, BoundaryError


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); f=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision != 1 or set(spec)!={"schema_version","specification_id","version","task","offline","invariants"} or spec["task"]!={"id":"AR-0072","revision":1} or spec["offline"]["execute"] is not False: raise BoundaryError("unsafe specification")
        b=Boundary(f["worktree"],f["capabilities"],f["limits"])
        for action in f["actions"]:
            if action["kind"]=="admit": b.admit(action["process_id"],action["lease_id"],action["command"],action["path"])
            elif action["kind"]=="cancel": b.cancel(action["process_id"],action["lease_id"])
            else: raise BoundaryError("unknown action")
        if b.snapshot()!=f["expected"]: raise BoundaryError("fixture mismatch")
        print(json.dumps({"contract":"awr-runtime-host-boundary@1.0.0","active":len(b.active),"execute":False,"network":b.limits["network"]},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,BoundaryError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

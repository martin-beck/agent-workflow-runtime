#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0073 transport."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.adapter_transport import Transport, TransportError


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); f=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision != 1 or set(spec)!={"schema_version","specification_id","version","task","offline","invariants"} or spec["task"]!={"id":"AR-0073","revision":1} or spec["offline"]["execute"] is not False: raise TransportError("unsafe specification")
        t=Transport(); t.admit(**f["binding"])
        for frame in f["frames"]: t.receive(frame["event"],frame["payload"])
        actual=t.export(); expected=f["expected"]
        if expected != {"state":actual["state"],"events":len(actual["events"]),"execute":actual["execute"],"network":actual["network"]}: raise TransportError("transport fixture mismatch")
        print(json.dumps({"contract":"awr-adapter-transport@1.0.0","events":len(t.events),"state":t.state,"execute":False},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,TransportError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

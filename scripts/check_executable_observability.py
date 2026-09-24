#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.executable_observability import ObservabilityError, Observer


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text()); f=json.loads(a.fixture.read_text())
        if a.expected_revision!=1 or spec["task"]!={"id":"AR-0078","revision":1} or spec["offline"]["execute"] is not False: raise ObservabilityError("unsafe specification")
        o=Observer();
        for event in f["events"]: o.observe(**event)
        actual=o.export()
        expected=f["expected"]
        if expected != {"events":len(actual["events"]),"counters":actual["counters"],"alerts":actual["alerts"],"execute":actual["execute"],"privacy":actual["privacy"],"remote":actual["remote"]}: raise ObservabilityError("observability fixture mismatch")
        print(json.dumps({"contract":"awr-executable-observability@1.0.0","events":len(o.events),"failed":o.counters["failed"],"execute":False,"remote":"unverified"},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,ObservabilityError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

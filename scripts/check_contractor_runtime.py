#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.contractor_runtime import LocalContractorRuntime, WorkflowError


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text()); f=json.loads(a.fixture.read_text())
        if a.expected_revision!=1 or spec["task"]!={"id":"AR-0077","revision":1} or spec["offline"]["execute"] is not False: raise WorkflowError("unsafe specification")
        r=LocalContractorRuntime(); actual=r.run_success(); expected=f["expected"]
        if expected != {"state":actual["state"],"attempt":actual["attempt"],"events":len(actual["events"]),"execute":actual["execute"],"quality":actual["quality"],"remote":actual["remote"]}: raise WorkflowError("fixture mismatch")
        print(json.dumps({"contract":"awr-local-contractor-runtime@1.0.0","state":r.state,"events":len(r.events),"execute":False,"remote":"unverified"},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,WorkflowError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

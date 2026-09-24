#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.codex_adapter import AdapterError, CodexAdapter


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text()); f=json.loads(a.fixture.read_text())
        if a.expected_revision!=1 or spec["task"]!={"id":"AR-0074","revision":1} or spec["offline"]["execute"] is not False: raise AdapterError("unsafe specification")
        x=CodexAdapter(); x.admit(**f["binding"]); x.request(f["request_digest"]); x.interrupt(); x.close()
        actual=x.export(); expected=f["expected"]
        if expected != {"provider":actual["provider"],"capabilities":actual["capabilities"],"state":actual["state"],"events":len(actual["events"]),"execute":actual["execute"],"network":actual["network"]}: raise AdapterError("fixture mismatch")
        print(json.dumps({"contract":"awr-codex-adapter@1.0.0","state":x.state,"events":len(x.events),"execute":False},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,AdapterError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

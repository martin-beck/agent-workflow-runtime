#!/usr/bin/env python3
"""Offline checker for AR-0068; it never starts a live pilot."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.pilot_gate import PilotError, evaluate


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); fixture=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision != 1 or set(spec)!={"schema_version","specification_id","version","task","execution","required_approvals","limitations"} or spec["task"]!={"id":"AR-0068","revision":1} or spec["execution"]["execute"] is not False: raise PilotError("unsupported or unsafe pilot specification")
        print(json.dumps(evaluate(fixture),sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,PilotError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())

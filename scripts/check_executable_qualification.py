#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.executable_qualification import QualificationError, validate


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text()); f=json.loads(a.fixture.read_text())
        if a.expected_revision!=1 or spec["task"]!={"id":"AR-0079","revision":1} or spec["offline"]["execute"] is not False: raise QualificationError("unsafe specification")
        print(json.dumps(validate(f),sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,QualificationError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

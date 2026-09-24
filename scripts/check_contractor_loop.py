#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0066."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.contractor_loop import ContractorError, validate


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); record=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision!=1 or set(spec)!={"schema_version","specification_id","version","task","offline","authorities","bounds"} or spec["task"]!={"id":"AR-0066","revision":1} or spec["offline"]["execute"] is not False: raise ContractorError("unsupported or unsafe specification")
        print(json.dumps(validate(record),sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,ContractorError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

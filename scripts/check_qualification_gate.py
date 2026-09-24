#!/usr/bin/env python3
"""Fail-closed checker for AR-0067 offline qualification evidence."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.qualification_gate import QualificationError, validate


def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument("--spec",required=True,type=Path); parser.add_argument("--fixture",required=True,type=Path); parser.add_argument("--expected-revision",required=True,type=int); args=parser.parse_args(argv)
    try:
        spec=json.loads(args.spec.read_text(encoding="utf-8")); fixture=json.loads(args.fixture.read_text(encoding="utf-8"))
        required={"schema_version","specification_id","version","task","offline","thresholds","limitations"}
        if args.expected_revision != 1 or set(spec) != required or spec["task"] != {"id":"AR-0067","revision":1} or spec["offline"]["execute"] is not False: raise QualificationError("unsupported or unsafe qualification specification")
        print(json.dumps(validate(fixture),sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,QualificationError) as exc:
        print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())

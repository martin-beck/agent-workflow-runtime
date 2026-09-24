#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0069."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.runtime_kernel import KernelError, RuntimeKernel


def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument("--spec",required=True,type=Path); parser.add_argument("--fixture",required=True,type=Path); parser.add_argument("--expected-revision",required=True,type=int); args=parser.parse_args(argv)
    try:
        spec=json.loads(args.spec.read_text(encoding="utf-8")); fixture=json.loads(args.fixture.read_text(encoding="utf-8"))
        required={"schema_version","specification_id","version","task","offline","invariants"}
        if args.expected_revision != 1 or set(spec) != required or spec["task"] != {"id":"AR-0069","revision":1} or spec["offline"]["execute"] is not False: raise KernelError("unsupported or unsafe specification")
        kernel=RuntimeKernel();
        for event in fixture["events"]: kernel.record(event["operation_id"],event["event"],event["lease_id"],event["usage"],event.get("payload"))
        result=kernel.snapshot(); expected=fixture["expected"]
        if expected != {"state":result["state"],"events":len(result["store"]["events"]),"usage":result["store"]["usage"],"execute":result["execute"],"network":result["network"],"provider":result["provider"],"llm":result["llm"]}: raise KernelError("kernel fixture mismatch")
        print(json.dumps({"contract":"awr-executable-runtime-kernel@1.0.0","events":len(result["store"]["events"]),"state":result["state"],"execute":False},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,KernelError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())

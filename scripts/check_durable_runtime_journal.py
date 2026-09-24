#!/usr/bin/env python3
"""Fail-closed offline AR-0070 journal checker."""
import argparse
import json
import sys
from pathlib import Path

if __package__ in (None,""): sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.durable_runtime_journal import Journal, RecoveryError


def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--fixture",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try:
        spec=json.loads(a.spec.read_text(encoding="utf-8")); fixture=json.loads(a.fixture.read_text(encoding="utf-8"))
        if a.expected_revision!=1 or set(spec)!={"schema_version","specification_id","version","task","offline","invariants"} or spec["task"]!={"id":"AR-0070","revision":1} or spec["offline"]["execute"] is not False: raise RecoveryError("unsupported or unsafe specification")
        journal=Journal(); checkpoints={}
        for action in fixture["actions"]:
            if action["kind"]=="append": journal.append(action["operation_id"],action["event"],action.get("payload"),action.get("fence",1))
            elif action["kind"]=="checkpoint": checkpoints[action["checkpoint_id"]]=journal.checkpoint(action["checkpoint_id"])
            elif action["kind"]=="crash":
                try: journal.append(action["operation_id"],action["event"],action.get("payload"),action.get("fence",1),True)
                except RecoveryError: pass
            elif action["kind"]=="recover": journal.recover(checkpoints[action["checkpoint_id"]],action["fence"])
            else: raise RecoveryError("unknown action")
        if fixture["expected"] != {"records":len(journal.records),"fence":journal.fence,"state":journal.state,"execute":False}: raise RecoveryError("journal fixture mismatch")
        print(json.dumps({"contract":"awr-durable-runtime-journal@1.0.0","records":len(journal.records),"state":journal.state,"fence":journal.fence,"execute":False},sort_keys=True,separators=(",",":"))); return 0
    except (OSError,json.JSONDecodeError,KeyError,TypeError,RecoveryError) as exc: print("REJECT: "+str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

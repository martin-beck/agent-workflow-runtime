#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0063 protocol traces."""
import argparse, json, re, sys
from pathlib import Path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.provider_adapter_protocol import CAPABILITIES, DIGEST, SECRET_REF, canonical_bytes, sha256

class ContractError(ValueError): pass
def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as f: return json.load(f)
    except (OSError, json.JSONDecodeError) as e: raise ContractError(f"malformed JSON: {e}") from e

def validate_spec(spec):
    required={"schema_version","specification_id","version","task","lifecycle","capabilities","boundaries","privacy","failure_semantics","limitations"}
    if not isinstance(spec,dict) or spec.get("schema_version") != 1 or not required <= set(spec) or spec["specification_id"] != "awr-provider-adapter-protocol" or spec["version"] != "1.0.0" or spec["task"] != {"id":"AR-0063","revision":5}: raise ContractError("invalid AR-0063 specification")
    if spec["capabilities"] != list(CAPABILITIES) or spec["lifecycle"]["terminal"] != ["closed","failed"] or spec["failure_semantics"]["mode"] != "fail_closed": raise ContractError("invalid protocol semantics")
    return True

def validate_trace(trace, expected_revision=5):
    if not isinstance(trace,list) or not trace or len(trace)>64: raise ContractError("trace must be bounded and non-empty")
    state="new"; binding=None; seen=set()
    for n, r in enumerate(trace,1):
        if not isinstance(r,dict) or r.get("sequence") != n: raise ContractError("sequence mismatch")
        forbidden={k for k in r if re.search(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output",k,re.I)}
        if forbidden: raise ContractError("privacy-bearing field")
        if r.get("state_before") != state or r.get("task") != {"id":"AR-0063","revision":expected_revision}: raise ContractError("binding or state mismatch")
        session=r.get("session",{})
        if set(session)!={"id","worktree_key","worktree_digest"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}",str(session["id"])) or not DIGEST.fullmatch(str(session["worktree_digest"])): raise ContractError("invalid session")
        if binding is None: binding=session
        elif session != binding: raise ContractError("crossed worktree")
        op=r.get("operation"); after=r.get("state_after"); disp=r.get("disposition")
        allowed={"admission":("new","admitted","admitted"),"discovery":("admitted","discovered","discovered"),"negotiation":("discovered",("ready","discovered"),("negotiated","unsupported")),"stream_open":(("ready","active"),"streaming","accepted"),"stream_chunk":("streaming","streaming","accepted"),"stream_end":("streaming","active","accepted"),"interrupt":(("ready","active","streaming"),"interrupted","acknowledged"),"checkpoint":(("ready","active","interrupted"),("ready","active","interrupted"),"recorded"),"resume":("interrupted","active","resumed"),"failure":(("ready","active","streaming","interrupted"),"failed","failed"),"close":(("ready","active","streaming","interrupted"),"closed",("completed","interrupted","cancelled"))}
        if op in {"request","tool","file_read","file_write"}:
            if state not in {"ready","active"} or after not in {"ready","active"} or disp not in {"accepted","unsupported"}: raise ContractError("invalid routed operation")
            if disp=="accepted" and not any(k in r and (DIGEST.fullmatch(str(r[k])) or SECRET_REF.fullmatch(str(r[k]))) for k in ("request_digest","reference")): raise ContractError("missing opaque reference")
        elif op not in allowed: raise ContractError("unknown operation")
        else:
            before, target, expected=allowed[op]; before=before if isinstance(before,tuple) else (before,); target=target if isinstance(target,tuple) else (target,); expected=expected if isinstance(expected,tuple) else (expected,)
            if state not in before or after not in target or disp not in expected: raise ContractError("invalid lifecycle transition")
        if op in {"request","tool","file_read","file_write"} and disp=="unsupported" and r.get("state_change") is not False: raise ContractError("unsupported changed state")
        state=after
    if state not in {"closed","failed"}: raise ContractError("trace must end terminal")
    return {"contract":"awr-provider-adapter-protocol@1.0.0","records":len(trace),"terminal_state":state}

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--spec",required=True,type=Path); p.add_argument("--trace",required=True,type=Path); p.add_argument("--expected-revision",required=True,type=int); a=p.parse_args(argv)
    try: validate_spec(load_json(a.spec)); result=validate_trace(load_json(a.trace),a.expected_revision)
    except ContractError as e: print(f"REJECT: {e}",file=sys.stderr); return 1
    print(json.dumps(result,sort_keys=True,separators=(",",":"))); return 0
if __name__ == "__main__": raise SystemExit(main())

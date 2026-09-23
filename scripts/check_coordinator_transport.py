#!/usr/bin/env python3
"""Offline transcript checker for the AR-0046 Coordinator transport."""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.coordinator_transport import CoordinatorTransportServer, CoordinatorTransportClient, TransportError, digest

CHECKER = "awr-coordinator-transport-checker/1.0.0"

def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream: return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc: raise TransportError("malformed JSON") from exc

def check(spec, record, expected_revision):
    if spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-coordinator-transport" or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise TransportError("unsupported specification")
    if record.get("task_revision") != expected_revision or record.get("task_id") != "AR-0046": raise TransportError("wrong task revision")
    binding = record.get("binding")
    if not isinstance(binding, dict): raise TransportError("missing binding")
    server = CoordinatorTransportServer(revision=expected_revision, project_revision=binding["project_revision"], worktree_digest=binding["worktree_digest"], auth_reference=binding["auth_reference"])
    for item in record.get("transcript", []):
        if item.get("expected_disposition") == "unknown_outcome":
            server.inject("ambiguous_after_commit")
        client = CoordinatorTransportClient(server, binding, max_attempts=record.get("max_attempts", 3))
        try:
            actual = client.call(item["operation"], item["operation_id"], item["expected_revision"], event_kind=item.get("event_kind"), event_digest=item.get("event_digest"), timeout_ms=item["timeout_ms"])
        except TransportError as exc:
            if item.get("expected_error") != str(exc): raise
            continue
        if actual != item.get("response"): raise TransportError("transcript response mismatch")
    evidence = record.get("evidence", {})
    if evidence.get("checker") != CHECKER or evidence.get("live_verification") != "unverified" or evidence.get("network") != "not_performed": raise TransportError("invalid evidence boundary")
    safe = dict(evidence); safe.pop("safe_digest", None)
    if evidence.get("safe_digest") != digest(safe): raise TransportError("evidence digest mismatch")
    return {"checker": CHECKER, "task_revision": expected_revision, "requests": len(record["transcript"]), "final_server_revision": server.revision, "live_verification": "unverified"}

def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--record", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try: print(json.dumps(check(load(args.spec), load(args.record), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (TransportError, KeyError, TypeError) as exc: print("REJECT: " + str(exc), file=sys.stderr); return 1
    return 0
if __name__ == "__main__": raise SystemExit(main())

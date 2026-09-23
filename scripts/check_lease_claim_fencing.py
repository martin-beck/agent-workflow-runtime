"""Offline checker for the AR-0047 lease/claim fencing fixture."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from scripts.lease_claim_fencing import LeaseError, LeaseStateMachine, AmbiguousCommit, canonical, digest
except ModuleNotFoundError:
    from lease_claim_fencing import LeaseError, LeaseStateMachine, AmbiguousCommit, canonical, digest

CHECKER = "awr-lease-claim-fencing-checker/1.0.0"


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise LeaseError("malformed JSON") from exc


def check(spec, record, expected_revision):
    if spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-lease-claim-fencing" or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise LeaseError("unsupported specification")
    if record.get("task_id") != "AR-0047" or record.get("task_revision") != expected_revision:
        raise LeaseError("wrong task revision")
    state = LeaseStateMachine(expected_revision)
    client = AmbiguousCommit(state) if record.get("ambiguous_operation") else state
    for item in record.get("operations", []):
        request = item["request"]
        try:
            actual = client.apply(request)
        except LeaseError as exc:
            if item.get("expected_error") != str(exc):
                raise
            continue
        if actual != item.get("response"):
            raise LeaseError("response mismatch")
    if state.journal:
        for index, entry in enumerate(state.journal):
            if entry["previous_digest"] != (state.journal[index - 1]["digest"] if index else "sha256:" + "0" * 64):
                raise LeaseError("broken journal chain")
            body = dict(entry); body.pop("digest")
            if entry["digest"] != digest(body):
                raise LeaseError("tampered journal")
    evidence = record.get("evidence", {})
    safe = dict(evidence); safe.pop("safe_digest", None)
    if evidence.get("checker") != CHECKER or evidence.get("live_verification") != "unverified" or evidence.get("network") != "not_performed" or evidence.get("safe_digest") != digest(safe):
        raise LeaseError("invalid evidence boundary")
    return {"checker": CHECKER, "task_revision": expected_revision, "operations": len(record["operations"]), "final_revision": state.revision, "owner": state.owner, "fence": state.fence, "live_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(check(load(args.spec), load(args.record), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (LeaseError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

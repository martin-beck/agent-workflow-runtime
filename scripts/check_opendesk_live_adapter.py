#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0035."""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.opendesk_live_adapter import CAPABILITIES, DIGEST, ID, SESSION, AdapterError, canonical, digest

CHECKER = "awr-opendesk-live-adapter-checker/1.0.0"
PROTOCOL = {"id": "awr-opendesk-live-provider", "version": "1.0.0"}


class ContractError(ValueError):
    pass


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError("malformed JSON") from exc


def _private(value):
    if isinstance(value, dict):
        return any(re.search(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output", str(k), re.I) or _private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_private(v) for v in value)
    return isinstance(value, str) and bool(re.search(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I))


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "normative", "task", "authority", "binding", "capabilities", "lifecycle", "gates", "compatibility", "privacy", "failure_semantics", "limitations"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != PROTOCOL["id"] or spec["version"] != PROTOCOL["version"] or spec["normative"] is not True:
        raise ContractError("unsupported specification")
    if spec["task"] != {"id": "AR-0035", "revision": 3} or spec["failure_semantics"].get("mode") != "fail_closed":
        raise ContractError("exact task binding and fail-closed mode required")
    if spec["capabilities"] != list(CAPABILITIES) or spec["gates"] != {"credentials": "not_required", "network": "disabled", "human_approval": "not_required", "provider": "not_performed"}:
        raise ContractError("capability or gate contract mismatch")
    return True


def validate_record(record, spec, expected_revision=3):
    validate_spec(spec)
    allowed = {"schema_version", "protocol", "task", "project", "worktree", "session", "events", "evidence", "execution"}
    if not isinstance(record, dict) or set(record) != allowed or record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise ContractError("malformed record")
    if _private(record) or record["task"] != {"id": "AR-0035", "revision": expected_revision} or expected_revision != 3:
        raise ContractError("privacy or stale revision")
    if record["execution"] != {"mode": "offline_fixture", "provider": "not_performed", "network": "disabled", "coordinator": "not_performed", "llm": "not_performed"}:
        raise ContractError("external execution claim")
    if not isinstance(record["events"], list) or not record["events"] or len(record["events"]) > 64:
        raise ContractError("bounded events required")
    state = "undiscovered"; binding = None; operations = set(); seen_digests = set(); awaiting = None
    for index, event in enumerate(record["events"], 1):
        if not isinstance(event, dict) or event.get("sequence") != index or event.get("event_digest") != digest({k: v for k, v in event.items() if k != "event_digest"}):
            raise ContractError("event digest or ordering mismatch")
        if event.get("state_before") != state or event.get("event_digest") in seen_digests:
            raise ContractError("state or replay mismatch")
        if event.get("task") != record["task"] or event.get("session") != record["session"] or event.get("adapter") != {"id": "opendesk-live", "version": "1.0.0"} or event.get("execute") is not False:
            raise ContractError("crossed binding or execution claim")
        seen_digests.add(event["event_digest"]); op = event.get("operation"); after = event.get("state_after")
        if op == "discover": ok = state == "undiscovered" and after == "discovered" and event.get("disposition") == "capabilities_reported"
        elif op == "negotiate": ok = state == "discovered" and after == "negotiated" and event.get("disposition") == "accepted" and set(event.get("negotiated_capabilities", [])) <= set(event.get("capabilities", CAPABILITIES))
        elif op == "start": ok = state == "negotiated" and after == "active" and event.get("disposition") == "started"
        elif op == "request":
            ok = state == "active" and after == "awaiting_response" and event.get("disposition") == "sent" and ID.fullmatch(str(event.get("operation_id"))) and event["operation_id"] not in operations and event.get("capability") in CAPABILITIES and DIGEST.fullmatch(str(event.get("request_digest")))
            if ok: operations.add(event["operation_id"]); awaiting = event["operation_id"]
        elif op == "response":
            ok = state == "awaiting_response" and after in {"active", "failed"} and event.get("operation_id") == awaiting and event.get("disposition") in {"completed", "failed"} and DIGEST.fullmatch(str(event.get("response_digest")))
            if ok: awaiting = None
        elif op == "interrupt": ok = state in {"active", "awaiting_response"} and after == "interrupted" and event.get("disposition") == "acknowledged" and DIGEST.fullmatch(str(event.get("checkpoint_digest")))
        elif op == "resume": ok = state == "interrupted" and after == "active" and event.get("disposition") == "resumed" and DIGEST.fullmatch(str(event.get("checkpoint_digest")))
        elif op == "close": ok = state == "active" and after == "completed" and event.get("disposition") == "closed"
        else: ok = False
        if not ok: raise ContractError("invalid lifecycle transition")
        state = after
    if state != "completed" or awaiting is not None:
        raise ContractError("fixture must end completed with no pending response")
    evidence = record["evidence"]
    if set(evidence) != {"checker", "specification_digest", "events_digest", "live_verification"} or evidence["checker"] != CHECKER or evidence["specification_digest"] != digest(spec) or evidence["events_digest"] != digest(record["events"]) or evidence["live_verification"] != "unverified":
        raise ContractError("evidence mismatch")
    return {"protocol": "awr-opendesk-live-provider@1.0.0", "task_revision": 3, "events": len(record["events"]), "final": state, "live_verification": "unverified"}


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--fixture", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try: print(json.dumps(validate_record(load(args.fixture), load(args.spec), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (ContractError, AdapterError, KeyError, TypeError) as exc: print("REJECT: " + str(exc), file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

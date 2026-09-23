#!/usr/bin/env python3
"""Offline fail-closed checker for AR-0050 provider adapter evidence."""

import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.provider_adapters import DIGEST, PROFILES, canonical_bytes, sha256


class ContractError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "adapters", "lifecycle", "policy", "errors", "privacy", "offline_boundary", "invariants", "limitations", "compatibility"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-production-provider-adapters" or spec["version"] != "1.0.0" or spec["task"] != {"id": "AR-0050", "revision": 5}:
        raise ContractError("unsupported or stale AR-0050 specification")
    for name, profile in PROFILES.items():
        configured = spec["adapters"].get(name)
        if not configured or configured["model_identity"] != profile.model or tuple(configured["capabilities"]) != profile.capabilities or configured["limits"] != profile.limits or tuple(configured["tools"]) != profile.tools or tuple(configured["files"]) != profile.files:
            raise ContractError(f"profile mismatch for {name}")
    if spec["offline_boundary"] != {"transport": "deterministic_fake_only", "provider": "not_performed", "network": "disabled", "llm": "not_performed", "credentials": "references_only", "live_verification": "unverified"}:
        raise ContractError("offline execution boundary is unsafe")
    return True


def _event_digest(event):
    body = dict(event); body.pop("evidence_digest", None); body.pop("event_digest", None)
    return sha256(canonical_bytes(body))


def validate_trace(name, trace, expected_revision=5):
    if name not in PROFILES or not isinstance(trace, list) or len(trace) != 6:
        raise ContractError("each adapter requires the bounded six-event conformance trace")
    profile = PROFILES[name]
    # Discovery is intentionally represented by the adapter-specific model and
    # capability report; the shared six-event fixture begins at negotiation.
    state = "discovered"; request_id = None; checkpoint = None; seen = set()
    expected = ["negotiate", "request", "stream", "interrupt", "resume", "close"]
    for sequence, event in enumerate(trace, 1):
        required = {"sequence", "operation", "state_before", "state_after", "task", "session", "adapter", "disposition", "evidence_digest", "event_digest"}
        if not isinstance(event, dict) or set(event) < required or event["sequence"] != sequence or event["operation"] != expected[sequence - 1] or event["task"] != {"id": "AR-0050", "revision": expected_revision} or event["adapter"]["id"] != name:
            raise ContractError(f"malformed {name} event")
        session = event["session"]
        if set(session) != {"id", "worktree_key", "worktree_digest"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]) or not DIGEST.fullmatch(session["worktree_digest"]):
            raise ContractError("invalid session binding")
        if event["state_before"] != state or not DIGEST.fullmatch(event["evidence_digest"]) or not DIGEST.fullmatch(event["event_digest"]) or event["event_digest"] != _event_digest(event):
            raise ContractError("state or digest mismatch")
        if event["operation"] == "negotiate":
            if event["state_after"] != "negotiated" or tuple(event["capabilities"]) != profile.capabilities or event["model"] != profile.model or not DIGEST.fullmatch(event["model_digest"]):
                raise ContractError("capability negotiation or model identity mismatch")
        elif event["operation"] == "request":
            if event["state_after"] != "active" or event["disposition"] != "accepted" or event.get("execute") is not False or not DIGEST.fullmatch(event["request_digest"]):
                raise ContractError("request correlation or execution policy mismatch")
            request_id = event["request_id"]
        elif event["operation"] == "stream":
            if event["state_after"] != "active" or event["request_id"] != request_id or event["redacted"] is not True or event["raw_output_absent"] is not True or len(event["frames"]) > profile.limits["max_stream_frames"]:
                raise ContractError("streaming policy mismatch")
            if [frame["sequence"] for frame in event["frames"]] != list(range(1, len(event["frames"]) + 1)) or any(not DIGEST.fullmatch(frame["digest"]) for frame in event["frames"]):
                raise ContractError("invalid stream frame correlation")
        elif event["operation"] == "interrupt":
            if event["state_after"] != "interrupted" or event["request_id"] != request_id or event["acknowledged"] is not True or not DIGEST.fullmatch(event["checkpoint_digest"]):
                raise ContractError("interruption is not acknowledged or fenced")
            checkpoint = event["checkpoint_digest"]
        elif event["operation"] == "resume":
            if event["state_after"] != "resumed" or event["request_id"] != request_id or event["checkpoint_digest"] != checkpoint:
                raise ContractError("resume crossed its checkpoint")
        elif event["operation"] == "close":
            if event["state_after"] != "completed" or event["request_id"] != request_id or event["success"] is not True:
                raise ContractError("close fabricated success")
        if event["event_digest"] in seen:
            raise ContractError("replayed event")
        seen.add(event["event_digest"]); state = event["state_after"]
    if state != "completed":
        raise ContractError("trace is not terminal")
    return {"adapter": name, "events": len(trace), "terminal_state": state, "live_verification": "unverified"}


def validate(record, expected_revision=5):
    fields = {"schema_version", "protocol", "task", "execution", "adapters", "evidence"}
    if not isinstance(record, dict) or set(record) != fields or record["schema_version"] != 1 or record["protocol"] != {"id": "awr-production-provider-adapters", "version": "1.0.0"} or record["task"] != {"id": "AR-0050", "revision": expected_revision} or expected_revision != 5:
        raise ContractError("invalid AR-0050 evidence envelope")
    if record["execution"] != {"transport": "deterministic_fake_only", "provider": "not_performed", "network": "disabled", "llm": "not_performed", "credentials": "references_only", "live_verification": "unverified"}:
        raise ContractError("provider execution was claimed")
    if set(record["adapters"]) != set(PROFILES):
        raise ContractError("all independent adapters are required")
    results = [validate_trace(name, record["adapters"][name], expected_revision) for name in sorted(PROFILES)]
    evidence = record["evidence"]
    if evidence != {"checker": "awr-production-provider-adapters-checker/1.0.0", "adapter_count": 3, "event_count": 18, "redacted": True, "live_verification": "unverified", "record_digest": evidence["record_digest"]} or evidence["record_digest"] != sha256(canonical_bytes({key: record[key] for key in record if key != "evidence"})):
        raise ContractError("redacted evidence digest mismatch")
    return {"contract": "awr-production-provider-adapters@1.0.0", "task_revision": 5, "adapters": results, "provider": "not_performed", "network": "disabled", "llm": "not_performed"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--record", required=True, type=Path); parser.add_argument("--expected-revision", required=True, type=int); args = parser.parse_args(argv)
    try:
        validate_spec(load_json(args.spec)); result = validate(load_json(args.record), args.expected_revision)
    except ContractError as exc:
        print(f"REJECT: {exc}", file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 0


if __name__ == "__main__":
    raise SystemExit(main())

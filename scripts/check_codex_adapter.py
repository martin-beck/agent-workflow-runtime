#!/usr/bin/env python3
"""Fail-closed offline checker for the AR-0015 replay trace."""

import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.codex_adapter import ADAPTER_ID, ADAPTER_VERSION, DIGEST, TASK_ID, canonical_bytes, sha256


class ContractError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "task", "authority", "capabilities", "lifecycle", "capability_report", "request", "invariants", "privacy", "limitations", "compatibility", "failure_semantics"}
    if not isinstance(spec, dict) or set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-codex-style-adapter" or spec["version"] != "1.0.0":
        raise ContractError("unsupported or incomplete specification")
    if spec["task"] != {"id": TASK_ID, "revision": 5} or spec["failure_semantics"].get("mode") != "fail_closed":
        raise ContractError("specification is not bound to AR-0015 revision 5")
    if spec["capabilities"] != ["discover", "start", "turn", "interrupt", "close", "fail"]:
        raise ContractError("invalid capability set")
    if spec["lifecycle"].get("states") != ["undiscovered", "discovered", "active", "interrupted", "closed", "failed"]:
        raise ContractError("invalid lifecycle")
    if not spec["limitations"] or not spec["privacy"]:
        raise ContractError("privacy and limitations are required")
    return True


def validate_trace(trace, expected_revision=5):
    if expected_revision != 5:
        raise ContractError("AR-0015 requires Coordinator revision 5")
    if not isinstance(trace, list) or not trace or len(trace) > 128:
        raise ContractError("trace must be a bounded non-empty array")
    state, turns, terminal = "undiscovered", 0, False
    seen = set()
    expected_session = None
    expected_adapter = None
    allowed = {
        ("undiscovered", "discover", "discovered"), ("discovered", "start", "active"),
        ("active", "turn", "active"), ("active", "interrupt", "interrupted"),
        ("active", "close", "closed"), ("active", "fail", "failed"),
    }
    for index, record in enumerate(trace, 1):
        required = {"sequence", "operation", "state_before", "state_after", "task", "session", "adapter", "evidence_digest"}
        if not isinstance(record, dict) or set(record) != required:
            raise ContractError("unknown or missing replay record field")
        if record["sequence"] != index or index in seen:
            raise ContractError("replayed or non-contiguous sequence")
        seen.add(index)
        if record["task"] != {"id": TASK_ID, "revision": expected_revision}:
            raise ContractError("stale task revision")
        session = record["session"]
        if (not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"}
                or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", str(session.get("id", "")))
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session.get("worktree_key", "")))
                or not DIGEST.fullmatch(str(session.get("worktree_digest", "")))):
            raise ContractError("invalid session binding")
        if record["adapter"] != {"id": ADAPTER_ID, "version": ADAPTER_VERSION}:
            raise ContractError("invalid adapter binding")
        if expected_session is None:
            expected_session, expected_adapter = session, record["adapter"]
        if session != expected_session or record["adapter"] != expected_adapter:
            raise ContractError("cross-session or adapter replay")
        if record["state_before"] != state or (state, record["operation"], record["state_after"]) not in allowed or terminal:
            raise ContractError("unauthorized lifecycle transition")
        if not DIGEST.fullmatch(str(record["evidence_digest"])):
            raise ContractError("invalid evidence digest")
        if any(re.search(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|executable", str(k), re.I) for k in record):
            raise ContractError("privacy violation")
        if any(re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", str(value), re.I) for value in record.values()):
            raise ContractError("private value violation")
        if record["operation"] == "turn":
            turns += 1
            if turns > 64:
                raise ContractError("turn limit exceeded")
        state = record["state_after"]
        terminal = state in {"interrupted", "closed", "failed"}
    if state not in {"interrupted", "closed", "failed"}:
        raise ContractError("trace must end terminal")
    return {"contract": "awr-codex-style-adapter@1.0.0", "records": len(trace), "task_revision": expected_revision, "terminal_state": state, "turns": turns}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load_json(args.spec))
        result = validate_trace(load_json(args.trace), args.expected_revision)
    except ContractError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline fail-closed checker for the AR-0003 adapter lifecycle trace."""

import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.agent_adapter import AdapterError


class ContractError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "task", "authority", "adapter", "lifecycle", "request", "invariants", "failure_semantics", "compatibility", "privacy", "limitations", "follow_up"}
    if not isinstance(spec, dict) or spec.get("schema_version") != 1 or not required.issubset(spec) or spec["specification_id"] != "awr-agent-adapter-lifecycle" or spec["version"] != "1.0.0":
        raise ContractError("unsupported or incomplete specification")
    if spec["task"] != {"id": "AR-0003", "revision": 5} or spec["failure_semantics"].get("mode") != "fail_closed":
        raise ContractError("specification task or failure binding is invalid")
    if spec["lifecycle"].get("states") != ["undiscovered", "discovered", "started", "active", "terminated", "failed"]:
        raise ContractError("invalid lifecycle states")
    if not spec["limitations"] or not spec["follow_up"]:
        raise ContractError("limitations and follow-up are required")
    return True


def validate_trace(trace, expected_revision=5):
    if not isinstance(trace, list) or not trace or len(trace) > 64:
        raise ContractError("trace must be a bounded non-empty array")
    state = "undiscovered"
    seen_sequences = set()
    terminal = False
    for index, record in enumerate(trace, 1):
        if not isinstance(record, dict):
            raise ContractError("lifecycle record must be an object")
        required = {"sequence", "operation", "state_before", "state_after", "task", "session", "adapter", "evidence_digest"}
        if set(record) != required:
            raise ContractError("unknown or missing lifecycle record field")
        if not isinstance(record.get("sequence"), int) or record["sequence"] != index or record["sequence"] in seen_sequences:
            raise ContractError("invalid or replayed sequence")
        seen_sequences.add(record["sequence"])
        if record.get("task") != {"id": "AR-0003", "revision": expected_revision}:
            raise ContractError("stale task revision")
        if not isinstance(record["session"], dict) or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", str(record["session"].get("id", ""))) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(record["session"].get("worktree_key", ""))):
            raise ContractError("invalid session binding")
        if record["adapter"] != {"id": "reference", "version": "1.0.0"}:
            raise ContractError("invalid adapter binding")
        if record.get("state_before") != state or record.get("state_after") not in {"undiscovered", "discovered", "started", "active", "terminated", "failed"}:
            raise ContractError("state transition mismatch")
        if terminal:
            raise ContractError("operation follows terminal state")
        operation = record.get("operation")
        allowed = {("undiscovered", "discover", "discovered"), ("discovered", "start", "started"), ("started", "interact", "active"), ("active", "interact", "active"), ("started", "terminate", "terminated"), ("active", "terminate", "terminated"), ("started", "fail", "failed"), ("active", "fail", "failed")}
        if (state, operation, record["state_after"]) not in allowed:
            raise ContractError("unauthorized lifecycle transition")
        if record.get("evidence_digest", "").startswith("sha256:") is False or not re.fullmatch(r"sha256:[0-9a-f]{64}", record.get("evidence_digest", "")):
            raise ContractError("invalid evidence digest")
        if any(re.search(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output", str(key), re.I) for key in record):
            raise ContractError("privacy violation")
        state = record["state_after"]
        terminal = state in {"terminated", "failed"}
    if state not in {"terminated", "failed"}:
        raise ContractError("trace must end terminal")
    return {"contract": "awr-agent-adapter-lifecycle@1.0.0", "records": len(trace), "task_revision": expected_revision, "terminal_state": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec = load_json(args.spec)
        validate_spec(spec)
        result = validate_trace(load_json(args.trace), args.expected_revision)
    except (ContractError, AdapterError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

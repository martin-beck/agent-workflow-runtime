#!/usr/bin/env python3
"""Offline fail-closed checker for the AR-0017 adapter contract."""

import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.opendesk_adapter import KNOWN_CAPABILITIES, DIGEST, SESSION, TASK, AdapterError, canonical_bytes, sha256


class ContractError(ValueError):
    pass


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"malformed JSON: {exc}") from exc


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "task", "authority", "adapter", "lifecycle", "request", "unsupported_capability", "invariants", "failure_semantics", "compatibility", "privacy", "limitations", "follow_up"}
    if not isinstance(spec, dict) or spec.get("schema_version") != 1 or not required.issubset(spec) or spec["specification_id"] != "awr-opendesk-style-adapter" or spec["version"] != "1.0.0":
        raise ContractError("unsupported or incomplete specification")
    if spec["task"] != {"id": "AR-0017", "revision": 5} or spec["failure_semantics"].get("mode") != "fail_closed":
        raise ContractError("specification task or failure binding is invalid")
    if spec["adapter"].get("known_capabilities") != list(KNOWN_CAPABILITIES) or spec["unsupported_capability"].get("state_change") is not False or spec["unsupported_capability"].get("execution") is not False:
        raise ContractError("capability semantics are invalid")
    if spec["lifecycle"].get("states") != ["undiscovered", "ready", "active", "terminated", "failed"] or not spec["limitations"]:
        raise ContractError("invalid lifecycle or limitations")
    return True


def validate_capability_report(report):
    if not isinstance(report, dict) or set(report) != {"adapter", "capabilities", "limits", "digest"}:
        raise ContractError("malformed capability report")
    if not isinstance(report["adapter"], dict) or set(report["adapter"]) != {"id", "version"} or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", str(report["adapter"]["id"])) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(report["adapter"]["version"])):
        raise ContractError("invalid capability identity")
    capabilities = report["capabilities"]
    if not isinstance(capabilities, list) or not capabilities or len(capabilities) > 16 or len(set(capabilities)) != len(capabilities) or any(capability not in KNOWN_CAPABILITIES for capability in capabilities):
        raise ContractError("invalid advertised capabilities")
    if report["limits"] != {"max_capabilities": 16, "max_request_digest": 72, "max_trace_records": 64} or not DIGEST.fullmatch(str(report["digest"])):
        raise ContractError("invalid capability limits or digest")
    body = {key: report[key] for key in ("adapter", "capabilities", "limits")}
    if report["digest"] != sha256(canonical_bytes(body)):
        raise ContractError("capability report digest mismatch")
    return True


def validate_trace(trace, expected_revision=5):
    if not isinstance(trace, list) or not trace or len(trace) > 64:
        raise ContractError("trace must be a bounded non-empty array")
    state = "undiscovered"
    binding = None
    for index, record in enumerate(trace, 1):
        if not isinstance(record, dict):
            raise ContractError("record must be an object")
        required = {"sequence", "operation", "state_before", "state_after", "disposition", "task", "session", "adapter"}
        allowed_keys = required | {"capability", "execute"}
        if set(record) != required and not (set(record) == allowed_keys or set(record) == allowed_keys | {"request_digest"}):
            raise ContractError("unknown or missing record field")
        if record["sequence"] != index or record["state_before"] != state or record["task"] != {"id": "AR-0017", "revision": expected_revision} or record["adapter"] != {"id": "opendesk-style", "version": "1.0.0"}:
            raise ContractError("sequence, state, revision, or adapter mismatch")
        session = record["session"]
        if not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"} or not SESSION.fullmatch(str(session.get("id", ""))) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", str(session.get("worktree_key", ""))) or not DIGEST.fullmatch(str(session.get("worktree_digest", ""))):
            raise ContractError("invalid session binding")
        if binding is None:
            binding = session
        elif session != binding:
            raise ContractError("worktree binding changed")
        if record["operation"] == "discover":
            allowed = state == "undiscovered" and record["state_after"] == "ready" and record["disposition"] == "discovered"
        elif record["operation"] == "start":
            allowed = state == "ready" and record["state_after"] == "active" and record["disposition"] == "started"
        elif record["operation"] == "request":
            allowed = state in {"ready", "active"} and record["state_after"] in {"ready", "active"} and record["disposition"] in {"accepted", "unsupported_capability"}
            if "capability" not in record or record["capability"] not in KNOWN_CAPABILITIES or record.get("execute") is not False:
                raise ContractError("invalid request capability semantics")
            if record["disposition"] == "accepted" and not DIGEST.fullmatch(str(record.get("request_digest", ""))):
                raise ContractError("accepted request requires a digest")
            if record["disposition"] == "unsupported_capability" and "request_digest" in record:
                raise ContractError("unsupported request must not expose an input payload")
            if record["disposition"] == "unsupported_capability" and record["state_after"] != state:
                raise ContractError("unsupported capability changed state")
        elif record["operation"] == "terminate":
            allowed = state in {"ready", "active"} and record["state_after"] == "terminated" and record["disposition"] in {"completed", "interrupted", "cancelled"}
        elif record["operation"] == "fail":
            allowed = state in {"ready", "active"} and record["state_after"] == "failed" and record["disposition"] == "failed"
        else:
            raise ContractError("unknown operation")
        if not allowed:
            raise ContractError("invalid lifecycle transition")
        if any(re.search(r"credential|password|secret|token|prompt|transcript|private.?path|raw.?output", str(key), re.I) for key in record):
            raise ContractError("privacy violation")
        state = record["state_after"]
    if state not in {"terminated", "failed"}:
        raise ContractError("trace must end terminal")
    return {"contract": "awr-opendesk-style-adapter@1.0.0", "records": len(trace), "task_revision": expected_revision, "terminal_state": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load_json(args.spec))
        result = validate_trace(load_json(args.trace), args.expected_revision)
    except (ContractError, AdapterError) as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

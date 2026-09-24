#!/usr/bin/env python3
"""Machine checker for the AR-0085 executable session contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CHECKER = "awr-agent-session-checker/1.0.0"
PROTOCOL = {"id": "awr-agent-session", "version": "1.0.0"}
REQUIRED_CASES = {
    "start_request_stream",
    "interruption_resume_close",
    "capability_mismatch",
    "stale_lease",
    "bounded_payload",
    "concurrent_profiles",
    "mock_boundary",
    "replay",
}


class CheckError(ValueError):
    pass


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc
    if not isinstance(value, dict):
        raise CheckError("object required")
    return value


def validate(spec: dict, fixture: dict, expected_revision: int) -> dict[str, object]:
    required_spec = {
        "schema_version", "specification_id", "version", "normative", "task",
        "dependencies", "lifecycle", "event_contract", "fencing", "bounds",
        "normalized_errors", "offline_boundary", "hostile_cases", "limitations",
    }
    if (
        set(spec) != required_spec or spec["schema_version"] != 1
        or spec["specification_id"] != PROTOCOL["id"]
        or spec["version"] != PROTOCOL["version"]
        or spec["normative"] is not True
        or spec["task"] != {"id": "AR-0085", "revision": expected_revision}
    ):
        raise CheckError("unsupported specification")
    if spec["dependencies"] != {"supervisor": "AR-0083", "registry": "AR-0084", "transport": "AR-0073"}:
        raise CheckError("dependency boundary changed")
    if spec["lifecycle"] != ["new", "started", "streaming", "interrupted", "closed", "failed"]:
        raise CheckError("lifecycle is incomplete")
    required_events = {"session_started", "request_accepted", "stream_chunk", "interrupted", "resumed", "closed"}
    if set(spec["event_contract"]) != {"required_fields", "event_types", "terminal_types"}:
        raise CheckError("event contract is malformed")
    if set(spec["event_contract"]["required_fields"]) != {
        "schema_version", "protocol", "event_id", "event_digest", "sequence", "event_type",
        "task", "session", "adapter", "correlation", "disposition", "details", "evidence_digest",
    } or set(spec["event_contract"]["event_types"]) != required_events or set(spec["event_contract"]["terminal_types"]) != {"closed", "failed", "interrupted"}:
        raise CheckError("event contract fields or types are incomplete")
    if spec["fencing"] != {
        "admission": "AR-0084 profile and AR-0083 lease",
        "operation": "same worker and lease before every operation",
        "resume": "exact interruption checkpoint and same lease",
        "stale": "blocked without process launch or state change",
    }:
        raise CheckError("fencing policy is unsafe")
    if spec["bounds"] != {
        "request": "profile max_request_bytes",
        "events": "profile max_output_events",
        "arguments": "AR-0083 bounded shell-free argv",
        "response": "AR-0083 output cap",
    }:
        raise CheckError("payload bounds are incomplete")
    if spec["normalized_errors"] != [
        "unknown_profile", "capability_mismatch", "stale_lease", "expired_lease",
        "payload_too_large", "invalid_state", "fence_mismatch", "supervisor_failure", "malformed_mock",
    ]:
        raise CheckError("normalized errors are incomplete")
    if spec["offline_boundary"] != {
        "provider": "not_performed", "backend": "not_performed", "credentials": "not_used",
        "network": "disabled", "llm": "not_performed", "local_mock": "deterministic_only",
        "durable_state": "not_performed", "remote_verification": "unverified",
    }:
        raise CheckError("unsafe external boundary")
    if set(spec["hostile_cases"]) != REQUIRED_CASES:
        raise CheckError("hostile coverage is incomplete")
    if not isinstance(spec["limitations"], list) or len(spec["limitations"]) < 3:
        raise CheckError("limitations are missing")

    required_fixture = {"schema_version", "protocol", "task", "profiles", "cases", "execution", "evidence"}
    if set(fixture) != required_fixture or fixture["schema_version"] != 1 or fixture["protocol"] != PROTOCOL:
        raise CheckError("malformed fixture envelope")
    if fixture["task"] != {"id": "AR-0085", "revision": expected_revision}:
        raise CheckError("wrong task revision")
    if fixture["profiles"] != ["codex-agent", "opencode-agent", "opendesk-agent", "generic-mock-agent"]:
        raise CheckError("concurrent profile corpus is incomplete")
    cases = fixture["cases"]
    if not isinstance(cases, list) or {case.get("name") for case in cases if isinstance(case, dict)} != REQUIRED_CASES:
        raise CheckError("required cases are missing")
    if any(not isinstance(case, dict) or set(case) != {"name", "expected", "state_change"} for case in cases):
        raise CheckError("malformed case")
    if fixture["execution"] != {
        "mode": "offline_fixture", "process": "local_deterministic_helper_only",
        "provider": "not_performed", "backend": "not_performed", "credentials": "not_used",
        "network": "disabled", "llm": "not_performed", "durable_state": "not_performed",
    }:
        raise CheckError("fixture claims external execution")
    if fixture["evidence"] != {"checker": CHECKER, "live_execution": "unverified", "replay": "deterministic_fixture"}:
        raise CheckError("evidence mismatch")
    return {
        "protocol": "awr-agent-session@1.0.0",
        "task_revision": expected_revision,
        "profiles": len(fixture["profiles"]),
        "cases": len(cases),
        "live_execution": "unverified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(validate(load(args.spec), load(args.fixture), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (CheckError, TypeError, KeyError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

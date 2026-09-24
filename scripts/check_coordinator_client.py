#!/usr/bin/env python3
"""Offline checker for the AR-0081 Coordinator client contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.coordinator_client import DIGEST, PATTERNS, CoordinatorClientError


def load(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise CoordinatorClientError("document_not_object")
    return value


def check_spec(spec: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "specification_id",
        "version",
        "title",
        "normative",
        "task",
        "authority",
        "binding",
        "operations",
        "request",
        "retry",
        "ambiguity",
        "failure_semantics",
        "evidence_boundary",
    }
    if (
        set(spec) != required
        or spec["schema_version"] != 1
        or spec["specification_id"] != "awr-executable-coordinator-client"
    ):
        raise CoordinatorClientError("invalid_specification_shape")
    if spec["normative"] is not True or spec["task"] != {
        "id": "AR-0081",
        "revision": 3,
    }:
        raise CoordinatorClientError("invalid_specification_binding")
    if spec["retry"].get("maximum_attempts") != 3 or set(
        spec["retry"].get("retryable", [])
    ) != {"unavailable", "deadline_exceeded", "timeout"}:
        raise CoordinatorClientError("invalid_retry_policy")
    if (
        spec["evidence_boundary"].get("network") != "disabled"
        or spec["evidence_boundary"].get("provider") != "not_performed"
    ):
        raise CoordinatorClientError("invalid_offline_boundary")


def _id(name: str, value: Any) -> None:
    if not isinstance(value, str) or not PATTERNS[name].fullmatch(value):
        raise CoordinatorClientError(f"invalid_{name}")


def check_record(
    record: dict[str, Any], spec: dict[str, Any], expected_revision: int = 3
) -> dict[str, Any]:
    check_spec(spec)
    if record.get("specification_id") != spec["specification_id"] or record.get(
        "task"
    ) != {"id": "AR-0081", "revision": expected_revision}:
        raise CoordinatorClientError("stale_record")
    binding = record.get("binding")
    if not isinstance(binding, dict) or set(binding) != {
        "task_id",
        "project_key",
        "worktree_key",
        "session_id",
        "owner_id",
        "lease_id",
        "auth_reference",
    }:
        raise CoordinatorClientError("invalid_binding")
    if (
        binding["task_id"] != "AR-0081"
        or binding["project_key"] != "agent-workflow-runtime"
    ):
        raise CoordinatorClientError("crossed_binding")
    for name in ("task_id", "session_id", "owner_id", "lease_id", "auth_reference"):
        _id(name, binding[name])
    if not isinstance(binding["worktree_key"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{0,127}", binding["worktree_key"]
    ):
        raise CoordinatorClientError("invalid_worktree_key")
    transcript = record.get("transcript")
    if not isinstance(transcript, list) or not transcript:
        raise CoordinatorClientError("missing_transcript")
    seen = set()
    revisions = []
    for item in transcript:
        if not isinstance(item, dict):
            raise CoordinatorClientError("invalid_transcript_entry")
        required = {
            "operation",
            "operation_id",
            "correlation_id",
            "expected_revision",
            "attempt",
            "response",
        }
        if not required.issubset(item) or set(item) - required - {
            "event_kind",
            "event_digest",
        }:
            raise CoordinatorClientError("invalid_request_shape")
        operation_id, correlation_id = item["operation_id"], item["correlation_id"]
        _id("operation_id", operation_id)
        _id("correlation_id", correlation_id)
        if (
            operation_id in seen
            or item["attempt"] not in range(1, 4)
            or item["expected_revision"] < 1
        ):
            raise CoordinatorClientError("invalid_operation_or_attempt")
        seen.add(operation_id)
        if item["operation"] not in {"read_revision", "write_event"}:
            raise CoordinatorClientError("unknown_operation")
        if item["operation"] == "write_event" and (
            not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", item.get("event_kind", ""))
            or not DIGEST.fullmatch(item.get("event_digest", ""))
        ):
            raise CoordinatorClientError("invalid_event")
        response = item["response"]
        if not isinstance(response, dict) or response.get("disposition") != "accepted":
            raise CoordinatorClientError("invalid_response")
        if (
            response.get("task_id") != "AR-0081"
            or response.get("correlation_id") != correlation_id
            or response.get("operation_id") != operation_id
        ):
            raise CoordinatorClientError("response_correlation_mismatch")
        if (
            not isinstance(response.get("task_revision"), int)
            or response["task_revision"] < 1
        ):
            raise CoordinatorClientError("invalid_response_revision")
        if (
            not isinstance(response.get("event_count"), int)
            or response["event_count"] < 0
        ):
            raise CoordinatorClientError("invalid_response_count")
        if item["operation"] == "read_revision":
            if not DIGEST.fullmatch(response.get("state_digest", "")):
                raise CoordinatorClientError("invalid_state_digest")
        elif response.get("event_digest") != item["event_digest"]:
            raise CoordinatorClientError("response_event_mismatch")
        revisions.append(response["task_revision"])
        if any(
            isinstance(value, str)
            and re.search(
                r"(?:password|token|credential|transcript|/home/)", value, re.IGNORECASE
            )
            for value in item.values()
        ):
            raise CoordinatorClientError("privacy_violation")
    evidence = record.get("evidence")
    if evidence != {
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
        "live_verification": "unverified",
    }:
        raise CoordinatorClientError("invalid_evidence_boundary")
    return {
        "operations": len(transcript),
        "final_revision": revisions[-1],
        "live_verification": "unverified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)
    args = parser.parse_args(argv)
    result = check_record(load(args.fixture), load(args.spec), args.expected_revision)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

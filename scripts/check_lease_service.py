#!/usr/bin/env python3
"""Offline checker for the AR-0082 shared lease boundary."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.lease_service import LeaseBinding, LeaseError, LocalCoordinatorFake, digest

CHECKER = "awr-shared-lease-service-checker/1.0.0"


def load(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise LeaseError("document_not_object")
    return value


def check_spec(spec: dict[str, Any]) -> None:
    required = {"schema_version", "specification_id", "version", "normative", "task",
                "binding", "operations", "invariants", "interleavings",
                "failure_semantics", "evidence_boundary"}
    if set(spec) != required or spec.get("schema_version") != 1 or spec.get(
        "specification_id"
    ) != "awr-shared-lease-service" or spec.get("version") != "1.0.0":
        raise LeaseError("invalid_specification_shape")
    if spec.get("normative") is not True or spec.get("task") != {"id": "AR-0082", "revision": 3}:
        raise LeaseError("invalid_specification_binding")
    if spec["evidence_boundary"] != {"network": "disabled", "provider": "not_performed", "llm": "not_performed"}:
        raise LeaseError("invalid_evidence_boundary")
    if set(spec["operations"]) != {"acquire", "heartbeat", "handoff", "recover_expired", "release"}:
        raise LeaseError("incomplete_operations")
    if len(spec["invariants"]) < 6 or spec["interleavings"].get("worker_bound") != 8:
        raise LeaseError("incomplete_invariants")


def check(spec: dict[str, Any], record: dict[str, Any], expected_revision: int) -> dict[str, Any]:
    check_spec(spec)
    if record.get("task") != {"id": "AR-0082", "revision": expected_revision}:
        raise LeaseError("stale_task_revision")
    binding_data = record.get("binding")
    if not isinstance(binding_data, dict) or set(binding_data) != {"task_id", "project_key", "worktree_key"}:
        raise LeaseError("invalid_binding")
    binding = LeaseBinding(**binding_data)
    binding.validate()
    if binding_data != spec["binding"]:
        raise LeaseError("binding_mismatch")
    fake = LocalCoordinatorFake(binding)
    accepted = 0
    fences: list[int] = []
    owners: list[str | None] = []
    for item in record.get("operations", []):
        if not isinstance(item, dict) or set(item) != {"request", "response"}:
            raise LeaseError("invalid_operation_record")
        actual = fake.apply(item["request"])
        if actual != item["response"]:
            raise LeaseError("response_mismatch")
        accepted += 1
        fences.append(actual["fence"])
        owners.append(actual["owner_id"])
    for item in record.get("counterexamples", []):
        if not isinstance(item, dict) or set(item) != {"request", "expected_error"}:
            raise LeaseError("invalid_counterexample")
        try:
            fake.apply(item["request"])
        except LeaseError as error:
            if str(error) != item["expected_error"]:
                raise LeaseError("counterexample_mismatch") from error
        else:
            raise LeaseError("counterexample_accepted")
    if fences != sorted(fences) or len({(entry["task_revision"], entry["fence"]) for entry in fake.journal}) != len(fake.journal):
        raise LeaseError("non_monotonic_fence_or_revision")
    if any(owner is not None and owners[index - 1] not in {None, owner} and fake.journal[index]["operation"] == "acquire" for index, owner in enumerate(owners) if index):
        raise LeaseError("double_owner")
    for index, entry in enumerate(fake.journal):
        expected_previous = fake.journal[index - 1]["digest"] if index else "sha256:" + "0" * 64
        if entry["previous_digest"] != expected_previous or entry["digest"] != digest({key: value for key, value in entry.items() if key != "digest"}):
            raise LeaseError("broken_journal")
    if record.get("evidence") != {"checker": CHECKER, "network": "disabled", "provider": "not_performed", "llm": "not_performed", "live_verification": "unverified"}:
        raise LeaseError("invalid_evidence")
    return {"checker": CHECKER, "operations": accepted, "counterexamples": len(record.get("counterexamples", [])), "final_revision": fake.revision, "final_owner": fake.owner_id, "fence": fake.fence, "live_verification": "unverified"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(check(load(args.spec), load(args.fixture), args.expected_revision), sort_keys=True))
    except (LeaseError, KeyError, TypeError) as error:
        print(f"REJECT: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline checker for the AR-0087 project isolation contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.project_isolation import (
    IsolationError,
    ProjectIsolationRegistry,
    RoutingContext,
    UnknownCleanupOutcome,
)


class CheckError(ValueError):
    pass


CHECKER = "awr-project-isolation-checker/1.0.0"


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc
    if not isinstance(value, dict):
        raise CheckError("record must be an object")
    return value


def validate_spec(spec: dict, expected_revision: int) -> None:
    required = {
        "schema_version",
        "specification_id",
        "version",
        "normative",
        "task",
        "authority_boundaries",
        "invariants",
        "hostile_qualification",
        "offline_boundary",
        "required_fixture_fields",
    }
    if (
        set(spec) != required
        or spec["schema_version"] != 1
        or spec["specification_id"] != "awr-multi-project-isolation"
        or spec["version"] != "1.0.0"
        or spec["normative"] is not True
    ):
        raise CheckError("unsupported_or_malformed_specification")
    if expected_revision != 3 or spec["task"] != {"id": "AR-0087", "revision": 3}:
        raise CheckError("unsupported_or_stale_task_revision")
    if spec["offline_boundary"] != {
        "checkout": "not_performed",
        "coordinator_write": "not_performed",
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
    }:
        raise CheckError("unsafe_offline_boundary")
    if len(spec["invariants"]) < 12 or len(spec["hostile_qualification"]) < 8:
        raise CheckError("incomplete_isolation_contract")
    if spec["required_fixture_fields"] != [
        "projects",
        "contexts",
        "actions",
        "expected",
    ]:
        raise CheckError("fixture_contract_changed")


def _context(value: dict) -> RoutingContext:
    fields = {
        "task_id",
        "task_revision",
        "tenant",
        "project_key",
        "project_revision",
        "worktree_key",
        "worker_id",
        "lease_id",
        "fence",
        "session_id",
        "coordinator_revision",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CheckError("malformed_context")
    try:
        result = RoutingContext(**value)
        result.validate()
        return result
    except (IsolationError, TypeError) as exc:
        raise CheckError(str(exc)) from exc


def validate_record(record: dict) -> dict:
    required = {"projects", "contexts", "actions", "expected"}
    if (
        set(record) != required
        or not isinstance(record["projects"], list)
        or not isinstance(record["contexts"], dict)
        or not isinstance(record["actions"], list)
    ):
        raise CheckError("unknown_or_missing_fixture_field")
    registry = ProjectIsolationRegistry()
    for project in record["projects"]:
        if not isinstance(project, dict) or set(project) != {
            "project_key",
            "tenant",
            "project_revision",
        }:
            raise CheckError("malformed_project")
        try:
            registry.register_project(**project)
        except (IsolationError, TypeError) as exc:
            raise CheckError(str(exc)) from exc
    contexts = {key: _context(value) for key, value in record["contexts"].items()}
    for action in record["actions"]:
        if not isinstance(action, dict) or "kind" not in action:
            raise CheckError("malformed_action")
        kind = action["kind"]
        try:
            if kind == "allocate":
                registry.allocate_worktree(contexts[action["context"]])
            elif kind == "publish":
                registry.put_artifact(
                    contexts[action["context"]],
                    action["artifact_id"],
                    action["payload"],
                )
            elif kind == "allow_dependency":
                source = registry.artifacts.get(
                    (
                        action["producer"],
                        action["source_worktree_key"],
                        action["artifact_id"],
                    )
                )
                if source is None:
                    raise CheckError("dependency source missing")
                registry.allow_dependency(
                    action["consumer"],
                    action["producer"],
                    action["artifact_id"],
                    source_worktree_key=action["source_worktree_key"],
                    content_digest=action["content_digest"],
                    provenance_digest=action["provenance_digest"],
                )
            elif kind == "read_dependency":
                registry.read_dependency(
                    contexts[action["context"]],
                    action["producer"],
                    action["artifact_id"],
                )
            elif kind == "cleanup_interrupted":
                try:
                    registry.cleanup_worktree(
                        contexts[action["context"]],
                        action["operation_id"],
                        interrupted=True,
                    )
                except UnknownCleanupOutcome:
                    pass
            elif kind == "recover_cleanup":
                registry.recover_cleanup(
                    contexts[action["context"]], action["operation_id"]
                )
            else:
                raise CheckError("unknown_action")
        except (IsolationError, KeyError, TypeError) as exc:
            raise CheckError(str(exc)) from exc
    snapshot = registry.snapshot()
    expected = record["expected"]
    actual = {
        "projects": len(snapshot["projects"]),
        "worktrees": len(snapshot["worktrees"]),
        "artifacts": len(snapshot["artifacts"]),
        "dependencies": len(snapshot["dependencies"]),
        "final_worktree_states": {
            project: next(
                item["state"]
                for key, item in snapshot["worktrees"].items()
                if key.startswith("WT-" + project.upper() + "-")
            )
            for project in snapshot["projects"]
        },
    }
    if actual != expected:
        raise CheckError("fixture_result_mismatch")
    return {
        "checker": CHECKER,
        **actual,
        "execute": False,
        "network": "disabled",
        "provider": "not_performed",
        "llm": "not_performed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        spec, record = load(args.spec), load(args.fixture)
        validate_spec(spec, args.expected_revision)
        result = validate_record(record)
    except (CheckError, KeyError, TypeError, ValueError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline machine checker for the AR-0089 project integration contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.project_integration import (
    IntegrationError,
    LocalAuthorityPort,
    LocalProjectFake,
    ProjectIntegrationRuntime,
    ProjectRegistration,
    SessionBoundary,
    TaskIntake,
)
from scripts.project_isolation import ProjectIsolationRegistry, RoutingContext

CHECKER = "awr-project-integration-checker/1.0.0"


class CheckError(ValueError):
    pass


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError("malformed JSON") from exc
    if not isinstance(value, dict):
        raise CheckError("record must be an object")
    return value


def validate_spec(spec: dict[str, Any], expected_revision: int) -> None:
    required = {
        "schema_version", "specification_id", "version", "normative", "task",
        "contract", "authority_boundaries", "invariants", "hostile_qualification",
        "offline_boundary", "required_fixture_fields",
    }
    if set(spec) != required or spec["schema_version"] != 1 or spec["specification_id"] != "awr-project-integration" or spec["version"] != "1.0.0" or spec["normative"] is not True:
        raise CheckError("unsupported_or_malformed_specification")
    if expected_revision != 3 or spec["task"] != {"id": "AR-0089", "revision": 3}:
        raise CheckError("unsupported_or_stale_task_revision")
    if not isinstance(spec["contract"], dict) or set(spec["contract"]) != {"registration", "intake", "capabilities", "artifacts", "evidence", "record_replay", "terminal"}:
        raise CheckError("incomplete_contract_surface")
    if len(spec["invariants"]) < 12 or len(spec["hostile_qualification"]) < 8:
        raise CheckError("incomplete_integration_contract")
    if spec["offline_boundary"] != {"network": "disabled", "provider": "not_performed", "llm": "not_performed", "coordinator_write": "not_performed", "checkout": "not_performed"}:
        raise CheckError("unsafe_offline_boundary")
    if spec["required_fixture_fields"] != ["projects", "contexts", "intakes", "sessions", "actions", "expected", "offline"]:
        raise CheckError("fixture_contract_changed")


def _context(value: Any) -> RoutingContext:
    fields = {"task_id", "task_revision", "tenant", "project_key", "project_revision", "worktree_key", "worker_id", "lease_id", "fence", "session_id", "coordinator_revision"}
    if not isinstance(value, dict) or set(value) != fields:
        raise CheckError("malformed_context")
    try:
        result = RoutingContext(**value)
        result.validate()
        return result
    except (IntegrationError, ValueError, TypeError) as exc:
        raise CheckError(str(exc)) from exc


def validate_record(record: dict[str, Any]) -> dict[str, Any]:
    required = {"projects", "contexts", "intakes", "sessions", "actions", "expected", "offline"}
    if set(record) != required or not all(isinstance(record[key], (list, dict)) for key in ("projects", "contexts", "intakes", "sessions", "actions")):
        raise CheckError("unknown_or_missing_fixture_field")
    if record["offline"] != {"network": "disabled", "provider": "not_performed", "llm": "not_performed", "coordinator_write": "not_performed", "checkout": "not_performed"}:
        raise CheckError("unsafe_offline_fixture")
    registry = ProjectIsolationRegistry()
    authority = LocalAuthorityPort(["accepted"])
    runtime = ProjectIntegrationRuntime(registry, authority)
    fake = LocalProjectFake(runtime)
    projects: dict[str, ProjectRegistration] = {}
    contexts = {key: _context(value) for key, value in record["contexts"].items()}
    intakes: dict[str, TaskIntake] = {}
    sessions: dict[str, SessionBoundary] = {}
    for item in record["projects"]:
        try:
            registration = ProjectRegistration(
                project_key=item["project_key"], tenant=item["tenant"], project_revision=item["project_revision"],
                capabilities=frozenset(item["capabilities"]), contract_version=item["contract_version"],
            )
            projects[item["project_key"]] = registration
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckError("malformed_project") from exc
    for key, item in record["intakes"].items():
        try:
            intakes[key] = TaskIntake(
                task_id=item["task_id"], task_revision=item["task_revision"], input_digest=item["input_digest"],
                required_capabilities=frozenset(item["required_capabilities"]), policy_reference=item.get("policy_reference"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckError("malformed_intake") from exc
    for key, item in record["sessions"].items():
        try:
            sessions[key] = SessionBoundary(
                session_id=item["session_id"], session_digest=item["session_digest"],
                adapter_capabilities=frozenset(item["adapter_capabilities"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckError("malformed_session") from exc
    runs: dict[str, str] = {}
    evidence: dict[str, dict[str, Any]] = {}
    for action in record["actions"]:
        if not isinstance(action, dict) or "kind" not in action:
            raise CheckError("malformed_action")
        try:
            kind = action["kind"]
            if kind == "register":
                runtime.register(projects[action["project"]])
            elif kind == "intake":
                run = runtime.intake(projects[action["project"]], intakes[action["intake"]], contexts[action["context"]], sessions[action["session"]])
                runs[action["project"]] = run
            elif kind == "begin":
                runtime.begin(runs[action["run"]], action["operation_id"])
            elif kind == "publish":
                runtime.publish_artifact(runs[action["run"]], action["artifact_id"], action["payload"])
            elif kind == "handoff":
                result = runtime.handoff_evidence(runs[action["run"]], action["artifact_id"], action["evidence_id"], action["evidence_payload"], operation_id=action["operation_id"], request_id=action["request_id"])
                evidence[action["run"]] = result["evidence"]
            elif kind == "terminal":
                digest = evidence[action["run"]]["evidence_digest"] if action.get("evidence_from_run") else None
                runtime.reconcile_terminal(runs[action["run"]], action["status"], terminal_payload=action["terminal_payload"], evidence_digest=digest, operation_id=action["operation_id"])
            elif kind == "terminal_replay":
                runtime.reconcile_terminal(runs[action["run"]], "succeeded", terminal_payload={"result": "ok"}, evidence_digest=evidence[action["run"]]["evidence_digest"], operation_id=action["operation_id"])
            elif kind == "record_replay":
                entry = fake.record(action["operation"], action["request"], action["response"])
                if fake.replay(action["operation"], action["request"]) != entry["response"]:
                    raise CheckError("record_replay_mismatch")
            else:
                raise CheckError("unknown_action")
        except (IntegrationError, KeyError, TypeError, ValueError) as exc:
            raise CheckError(str(exc)) from exc
    snapshot = runtime.snapshot()
    expected = record["expected"]
    actual = {
        "projects": len(snapshot["projects"]),
        "runs": len(snapshot["runs"]),
        "terminal_state": next(iter(snapshot["runs"].values()))["state"],
        "artifacts": sum(len(item["artifacts"]) for item in snapshot["runs"].values()),
        "events": len(snapshot["events"]),
        "recorded": len(fake.recorded),
    }
    if actual != expected:
        raise CheckError("fixture_result_mismatch")
    return {"checker": CHECKER, **actual, "execute": False, **record["offline"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        validate_spec(load(args.spec), args.expected_revision)
        result = validate_record(load(args.fixture))
    except (CheckError, KeyError, TypeError, ValueError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

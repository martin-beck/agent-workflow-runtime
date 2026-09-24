"""Deterministic local mock of the project-to-terminal workflow boundary.

This model consumes only supplied manifest bytes and synthetic events. It never
contacts or mutates Coordinator, AWQ, AWG, UI, a provider, or a network service.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from awr_cli.cli import canonical, initialize_mock, make_plan, validate_manifest

PROTOCOL = {"id": "awr-local-project-workflow", "version": "1.0.0"}
SPECIFICATION = {
    "schema_version": 1,
    "protocol": PROTOCOL,
    "task_revision": 1,
    "events": [
        ["coordinator", "task_admitted"],
        ["runtime", "worker_started"],
        ["worker", "change_proposed"],
        ["worker", "tests_passed"],
        ["awq", "quality_accepted"],
        ["awg", "repair_resolved"],
        ["ui", "human_gate_accepted"],
        ["coordinator", "terminal_reconciled"],
    ],
    "offline": {"provider": "not_performed", "network": "disabled", "llm": "not_performed"},
}
SPECIFICATION_DIGEST = "sha256:" + hashlib.sha256(canonical(SPECIFICATION)).hexdigest()
TEST_CONTRACT = {
    "positive": ["deterministic_replay", "terminal_reconciliation"],
    "hostile": ["skipped_awq", "skipped_awg", "skipped_ui", "changed_tests", "changed_specification", "unresolved_repair", "stale_revision", "replay"],
}
TEST_CONTRACT_DIGEST = "sha256:" + hashlib.sha256(canonical(TEST_CONTRACT)).hexdigest()
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class WorkflowError(ValueError):
    """Invalid or hostile local workflow evidence."""


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _event(sequence: int, authority: str, kind: str, revision: str) -> dict[str, Any]:
    body = {
        "sequence": sequence,
        "event_id": f"EVT-LOCAL-{sequence:02d}",
        "authority": authority,
        "kind": kind,
        "project_revision": revision,
        "evidence_digest": digest({"sequence": sequence, "kind": kind, "revision": revision}),
    }
    return body


def run(manifest_bytes: bytes, expected_revision: str | None = None) -> dict[str, Any]:
    """Create a deterministic trace and exercise the existing AWR bootstrap API."""
    manifest, revision = validate_manifest(manifest_bytes)
    if expected_revision is not None and expected_revision != revision:
        raise WorkflowError("stale_project_revision")
    plan = make_plan(manifest, revision, "local/mock-workflow", expected_revision)
    with tempfile.TemporaryDirectory(prefix="awr-local-project-") as temporary:
        initialized = initialize_mock(manifest, revision, Path(temporary) / "workspace")
        layout = json.loads((Path(temporary) / "workspace/.awr/local-mock/state.json").read_text())
        if initialized["status"] != "created" or layout["project_revision"] != revision:
            raise WorkflowError("bootstrap_layout_mismatch")
    names = SPECIFICATION["events"]
    events = [_event(i, authority, kind, revision) for i, (authority, kind) in enumerate(names, 1)]
    body = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "task": {"id": "LOCAL-WORKFLOW", "revision": 1},
        "project": {"name": manifest["project"]["name"], "revision": revision},
        "specification_digest": SPECIFICATION_DIGEST,
        "test_contract_digest": TEST_CONTRACT_DIGEST,
        "plan_digest": plan["plan_digest"],
        "layout_digest": digest({"status": initialized["status"], "layout": initialized["layout"], "state_revision": layout["project_revision"]}),
        "offline": {"provider": "not_performed", "network": "disabled", "llm": "not_performed", "durable_authority": "not_performed"},
        "events": events,
        "terminal": {"status": "reconciled", "coordinator": "observation_only", "publish": "not_performed", "remote_verification": "unverified"},
    }
    return {**body, "record_digest": digest(body)}


def validate(record: dict[str, Any], expected_project_revision: str | None = None) -> dict[str, Any]:
    required = {"schema_version", "protocol", "task", "project", "specification_digest", "test_contract_digest", "plan_digest", "layout_digest", "offline", "events", "terminal", "record_digest"}
    if not isinstance(record, dict) or set(record) != required:
        raise WorkflowError("malformed_record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "LOCAL-WORKFLOW", "revision": 1}:
        raise WorkflowError("unsupported_or_stale_task")
    project = record["project"]
    if not isinstance(project, dict) or set(project) != {"name", "revision"} or not DIGEST.fullmatch(str(project["revision"])):
        raise WorkflowError("invalid_project_binding")
    if expected_project_revision is not None and project["revision"] != expected_project_revision:
        raise WorkflowError("stale_project_revision")
    if record["specification_digest"] != SPECIFICATION_DIGEST:
        raise WorkflowError("changed_specification")
    if record["test_contract_digest"] != TEST_CONTRACT_DIGEST:
        raise WorkflowError("changed_test_contract")
    for field in ("plan_digest", "layout_digest"):
        if not isinstance(record[field], str) or not DIGEST.fullmatch(record[field]):
            raise WorkflowError("invalid_" + field)
    if record["offline"] != {"provider": "not_performed", "network": "disabled", "llm": "not_performed", "durable_authority": "not_performed"}:
        raise WorkflowError("external_effect_claim")
    events = record["events"]
    expected = SPECIFICATION["events"]
    if not isinstance(events, list) or len(events) != len(expected):
        raise WorkflowError("skipped_or_extra_gate")
    seen: set[str] = set()
    for index, (event, (authority, kind)) in enumerate(zip(events, expected), 1):
        if not isinstance(event, dict) or set(event) != {"sequence", "event_id", "authority", "kind", "project_revision", "evidence_digest"}:
            raise WorkflowError("malformed_event")
        if event["sequence"] != index or event["event_id"] in seen:
            raise WorkflowError("replayed_or_reordered_event")
        if event["authority"] != authority or event["kind"] != kind:
            raise WorkflowError("authority_gate_or_order_violation")
        if event["project_revision"] != project["revision"]:
            raise WorkflowError("stale_event_revision")
        if event["evidence_digest"] != digest({"sequence": index, "kind": kind, "revision": project["revision"]}):
            raise WorkflowError("event_evidence_mismatch")
        seen.add(event["event_id"])
    if record["terminal"] != {"status": "reconciled", "coordinator": "observation_only", "publish": "not_performed", "remote_verification": "unverified"}:
        raise WorkflowError("terminal_reconciliation_failure")
    if record["record_digest"] != digest({key: value for key, value in record.items() if key != "record_digest"}):
        raise WorkflowError("record_digest_mismatch")
    return {"status": "reconciled", "events": len(events), "project_revision": project["revision"], "provider": "not_performed", "network": "disabled"}


#!/usr/bin/env python3
"""Offline AWG live-oracle transport and decision-binding harness for AR-0038."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-awg-live-oracle", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^(?:AR|ALT|DEC|EVID|EVT|OP|CHK|SES|GUIDE|REQ)-[A-Z0-9-]{1,63}$")
VERSION = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data|authorization|cookie)", re.I)
DECISION_WORDS = re.compile(r"(?:selected|winner|approved|rejected|decision|guidance|recommendation)", re.I)
RESULTS = {"passed", "failed", "blocked", "skipped", "not_run"}
UNCERTAINTY = {"low", "medium", "high"}


class OracleError(ValueError):
    """A fail-closed contract violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise OracleError("malformed " + name)
    return value


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and (PRIVATE.search(value) or DECISION_WORDS.search(value) and value not in {"not_decided", "not_received", "awg_external_observation"}):
        errors.append(location)
    return errors


def _binding(record):
    return {key: record[key] for key in ("task", "project", "worktree", "session", "request")}


def validate(record, expected_revision=3, *, expected_task="AR-0038", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0038"):
    top = {"schema_version", "protocol", "task", "project", "worktree", "session", "request", "tool_versions", "observations", "uncertainty", "transport", "response"}
    _object(record, top, "oracle record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise OracleError("unsupported oracle protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or not re.fullmatch(r"AR-[0-9]{4}", task["id"]):
        raise OracleError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    session = _object(record["session"], {"id"}, "session")
    request = _object(record["request"], {"id", "attempt", "input_digest"}, "request")
    if project["key"] != expected_project or not HEX.fullmatch(project["revision"]):
        raise OracleError("invalid project binding")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise OracleError("invalid worktree binding")
    if not ID.fullmatch(session["id"]):
        raise OracleError("invalid session binding")
    if not ID.fullmatch(request["id"]) or not request["id"].startswith("REQ-") or request["attempt"] != 1 or not DIGEST.fullmatch(request["input_digest"]):
        raise OracleError("invalid request binding")

    tools = record["tool_versions"]
    if not isinstance(tools, list) or not tools or len(tools) > 8:
        raise OracleError("invalid tool versions")
    seen = set()
    for tool in tools:
        _object(tool, {"id", "version"}, "tool version")
        if not ID.fullmatch(tool["id"]) or tool["id"] in seen or not VERSION.fullmatch(tool["version"]):
            raise OracleError("invalid tool version")
        seen.add(tool["id"])

    observations = record["observations"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 16:
        raise OracleError("invalid observation count")
    seen_ids, seen_digests = set(), set()
    for sequence, item in enumerate(observations, 1):
        _object(item, {"id", "sequence", "result", "evidence_digest"}, "observation")
        if item["sequence"] != sequence or not isinstance(item["sequence"], int) or isinstance(item["sequence"], bool) or not ID.fullmatch(item["id"]):
            raise OracleError("invalid observation")
        if item["id"] in seen_ids or item["result"] not in RESULTS or not DIGEST.fullmatch(item["evidence_digest"]) or item["evidence_digest"] in seen_digests:
            raise OracleError("replayed or invalid observation")
        seen_ids.add(item["id"]); seen_digests.add(item["evidence_digest"])
    uncertainty = _object(record["uncertainty"], {"level", "context_digest"}, "uncertainty")
    if uncertainty["level"] not in UNCERTAINTY or not DIGEST.fullmatch(uncertainty["context_digest"]):
        raise OracleError("invalid uncertainty")

    transport = _object(record["transport"], {"operation_id", "state", "network", "auth_state", "approval", "events"}, "transport")
    if not ID.fullmatch(transport["operation_id"]) or not transport["operation_id"].startswith("OP-") or transport["state"] != "interrupted" or transport["network"] != "not_performed" or transport["auth_state"] != "not_supplied" or transport["approval"] != "not_granted":
        raise OracleError("transport is not fail-closed")
    events = transport["events"]
    if not isinstance(events, list) or len(events) != 3:
        raise OracleError("invalid transport events")
    for sequence, event in enumerate(events, 1):
        _object(event, {"id", "sequence", "kind"}, "transport event")
        if event["sequence"] != sequence or not ID.fullmatch(event["id"]) or event["kind"] != ("prepare", "checkpoint", "interrupt")[sequence - 1]:
            raise OracleError("invalid transport order")

    response = _object(record["response"], {"id", "attempt", "request_id", "status", "decision_status", "decision_digest", "guidance_digest", "binding_digest", "source"}, "response")
    if not ID.fullmatch(response["id"]) or not response["id"].startswith("DEC-") or response["attempt"] != 1 or response["request_id"] != request["id"]:
        raise OracleError("invalid response correlation")
    if response["status"] != "not_received" or response["decision_status"] != "not_decided" or response["source"] != "awg_external_observation":
        raise OracleError("manufactured oracle response")
    if response["decision_digest"] is not None or response["guidance_digest"] is not None:
        raise OracleError("decision payload crossed offline boundary")
    if response["binding_digest"] != sha256(canonical_bytes(_binding(record))):
        raise OracleError("response binding digest mismatch")
    if _safe(record):
        raise OracleError("privacy-bearing or decision-injected record")
    return {"observations": len(observations), "task_revision": expected_revision, "session_id": session["id"], "transport_state": transport["state"], "decision_status": response["decision_status"]}


def project(record, specification_digest):
    if not DIGEST.fullmatch(specification_digest):
        raise OracleError("invalid specification digest")
    validate(record, record["task"]["revision"], expected_task=record["task"]["id"], expected_project=record["project"]["key"], expected_worktree=record["worktree"]["key"])
    projection = {"protocol": "awr-awg-live-oracle@1.0.0", "kind": "oracle_transport_observation", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"], "request": record["request"], "transport": {"operation_id": record["transport"]["operation_id"], "state": record["transport"]["state"], "network": "not_performed"}, "response": {"id": record["response"]["id"], "status": "not_received", "decision_status": "not_decided", "source": "awg_external_observation"}, "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection


class OfflineHarness:
    """Deterministic supplied-fixture harness; it never opens live transport."""

    def __init__(self, specification, record):
        self.specification, self.record = specification, record

    def qualify(self, expected_revision=3):
        result = validate(self.record, expected_revision)
        digest = sha256(canonical_bytes(self.specification))
        return {**result, "specification_digest": digest, "projection": project(self.record, digest), "live_verification": "unverified"}

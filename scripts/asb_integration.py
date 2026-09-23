#!/usr/bin/env python3
"""Deterministic offline ASB integration model for AR-0055."""

import hashlib
import json
import re


PROTOCOL = {"id": "awr-asb-integration", "version": "1.0.0"}
TASK = {"id": "AR-0055", "revision": 5}
STAGES = (
    "setup_init",
    "add_first_agent",
    "agent_connection",
    "preflight_eligibility",
    "benchmark_run",
    "extend_identical_configuration",
    "llm_record_replay",
    "interrupt_recovery",
    "comparison",
)
STATES = ("new", "initialized", "agent_added", "connected", "eligible", "run_not_performed", "extended", "replayed", "recovered", "compared")
TRANSITIONS = dict(zip(STAGES, zip(STATES, STATES[1:])))
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|network.?address|command|executable", re.I)


class IntegrationError(ValueError):
    """Fail-closed AR-0055 contract violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return all((str(key) in {"credentials"} or not PRIVATE.search(str(key))) and _safe(child) for key, child in value.items())
    if isinstance(value, list):
        return all(_safe(child) for child in value)
    return not (isinstance(value, str) and value not in {"reference_only", "references_only"} and (len(value) > 256 or PRIVATE.search(value)))


def _fields(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise IntegrationError("malformed " + name)
    return value


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise IntegrationError("invalid " + name)


def _claims(value):
    expected = {"execute", "benchmark", "provider", "network", "llm", "durable_state", "remote_verification"}
    if value != {"execute": False, "benchmark": "not_performed", "provider": "not_performed", "network": "disabled", "llm": "not_performed", "durable_state": "not_performed", "remote_verification": "unverified"}:
        raise IntegrationError("unsafe execution claim")
    _fields(value, expected, "claims")


def validate(record, expected_revision=5):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "trace", "terminal", "evidence"}
    _fields(record, required, "record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "AR-0055", "revision": expected_revision} or expected_revision != 5:
        raise IntegrationError("unsupported or stale AR-0055 record")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64}:
        raise IntegrationError("invalid project binding")
    if record["worktree"] != {"key": "agent-workflow-runtime-0055", "digest": "sha256:" + "2" * 64}:
        raise IntegrationError("invalid worktree binding")
    session = _fields(record["session"], {"id"}, "session")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]):
        raise IntegrationError("invalid session binding")
    if not _safe(record):
        raise IntegrationError("privacy-bearing record")
    binding = {key: record[key] for key in ("task", "project", "worktree", "session")}
    binding_digest = digest(binding)
    trace = record["trace"]
    if not isinstance(trace, list) or len(trace) != len(STAGES):
        raise IntegrationError("incomplete ASB workflow")
    state = "new"
    seen_ops, seen_evidence = set(), set()
    agents = []
    configuration_digest = None
    benchmark_digest = None
    for sequence, event in enumerate(trace, 1):
        fields = {"sequence", "operation_id", "stage", "state_before", "state_after", "status", "binding_digest", "input_digest", "evidence_digest", "claims", "bounds", "cancellation", "details"}
        _fields(event, fields, "workflow event")
        stage = STAGES[sequence - 1]
        before, after = TRANSITIONS[stage]
        if event["sequence"] != sequence or event["stage"] != stage or event["state_before"] != before or event["state_after"] != after or state != before:
            raise IntegrationError("workflow ordering or state violation")
        if not ID.fullmatch(event["operation_id"]) or event["operation_id"] in seen_ops:
            raise IntegrationError("replayed operation")
        if event["binding_digest"] != binding_digest or event["status"] != "observed":
            raise IntegrationError("crossed binding or status")
        _digest(event["input_digest"], "input digest")
        _digest(event["evidence_digest"], "evidence digest")
        body = dict(event); body.pop("evidence_digest")
        if event["evidence_digest"] != digest(body) or event["evidence_digest"] in seen_evidence:
            raise IntegrationError("tampered or replayed evidence")
        _claims(event["claims"])
        bounds = _fields(event["bounds"], {"max_events", "max_agents", "max_bytes", "max_retries"}, "bounds")
        if bounds != {"max_events": 16, "max_agents": 8, "max_bytes": 4096, "max_retries": 1}:
            raise IntegrationError("invalid bounds")
        cancellation = _fields(event["cancellation"], {"requested", "acknowledged"}, "cancellation")
        if not all(isinstance(cancellation[key], bool) for key in cancellation) or cancellation["acknowledged"] and not cancellation["requested"]:
            raise IntegrationError("invalid cancellation acknowledgement")
        details = event["details"]
        if not isinstance(details, dict) or not _safe(details):
            raise IntegrationError("invalid event details")
        if stage == "setup_init":
            _fields(details, {"setup", "control_protocol", "ui_projection"}, "setup details")
            if details != {"setup": "accepted", "control_protocol": "asb-control-v1", "ui_projection": "runner_authoritative"}:
                raise IntegrationError("setup was not accepted")
        elif stage == "add_first_agent":
            _fields(details, {"agent_id", "agent_digest", "configuration_digest", "agent_count"}, "agent details")
            _digest(details["agent_digest"], "agent digest"); _digest(details["configuration_digest"], "configuration digest")
            if not ID.fullmatch(details["agent_id"]) or details["agent_count"] != 1:
                raise IntegrationError("invalid first agent")
            agents.append(details["agent_id"]); configuration_digest = details["configuration_digest"]
        elif stage == "agent_connection":
            _fields(details, {"agent_id", "connection", "connection_digest", "transport"}, "connection details")
            _digest(details["connection_digest"], "connection digest")
            if details["agent_id"] != agents[0] or details["connection"] != "accepted" or details["transport"] != "offline_fake":
                raise IntegrationError("invalid agent connection")
        elif stage == "preflight_eligibility":
            _fields(details, {"agent_id", "catalog", "setup", "credentials", "host", "network", "capabilities", "benchmark_eligibility", "preflight_digest"}, "preflight details")
            _digest(details["preflight_digest"], "preflight digest")
            if details["agent_id"] != agents[0] or details["catalog"] != "accepted" or details["setup"] != "accepted" or details["credentials"] != "reference_only" or details["host"] != "pass" or details["network"] != "pass" or details["capabilities"] != "supported" or details["benchmark_eligibility"] != "eligible":
                raise IntegrationError("agent is not eligible")
        elif stage == "benchmark_run":
            _fields(details, {"benchmark_digest", "run_status", "measurement", "reason"}, "run details")
            _digest(details["benchmark_digest"], "benchmark digest")
            benchmark_digest = details["benchmark_digest"]
            if details != {"benchmark_digest": benchmark_digest, "run_status": "not_performed", "measurement": "not_performed", "reason": "offline_boundary"}:
                raise IntegrationError("benchmark execution claimed")
        elif stage == "extend_identical_configuration":
            _fields(details, {"agent_id", "existing_agent_id", "agent_digest", "configuration_digest", "identical_configuration", "agent_count"}, "extension details")
            _digest(details["agent_digest"], "agent digest"); _digest(details["configuration_digest"], "configuration digest")
            if details["existing_agent_id"] != agents[0] or details["agent_id"] in agents or details["configuration_digest"] != configuration_digest or details["identical_configuration"] is not True or details["agent_count"] != 2:
                raise IntegrationError("configuration fan-out is not identical")
            agents.append(details["agent_id"])
        elif stage == "llm_record_replay":
            _fields(details, {"mode", "request_digest", "response_digest", "cassette_digest", "network", "match"}, "record replay details")
            for key in ("request_digest", "response_digest", "cassette_digest"): _digest(details[key], key)
            if details["mode"] != "record_then_replay" or details["network"] != "disabled" or details["match"] is not True:
                raise IntegrationError("record/replay boundary violation")
        elif stage == "interrupt_recovery":
            _fields(details, {"checkpoint_digest", "interrupted", "recovered", "recovery_fence"}, "recovery details")
            _digest(details["checkpoint_digest"], "checkpoint digest")
            if details != {"checkpoint_digest": details["checkpoint_digest"], "interrupted": True, "recovered": True, "recovery_fence": "new_attempt_same_configuration"} or cancellation != {"requested": True, "acknowledged": True}:
                raise IntegrationError("interruption was not fenced")
        elif stage == "comparison":
            _fields(details, {"benchmark_digest", "configuration_digest", "agent_ids", "comparison", "measurement", "result_digest"}, "comparison details")
            _digest(details["benchmark_digest"], "comparison benchmark digest"); _digest(details["configuration_digest"], "comparison configuration digest"); _digest(details["result_digest"], "comparison result digest")
            if details["benchmark_digest"] != benchmark_digest or details["configuration_digest"] != configuration_digest or details["agent_ids"] != agents or len(details["agent_ids"]) < 2 or details["comparison"] != "structurally_comparable" or details["measurement"] != "not_performed":
                raise IntegrationError("invalid comparison")
        state = after; seen_ops.add(event["operation_id"]); seen_evidence.add(event["evidence_digest"])
    if record["terminal"] != {"status": "qualified_offline", "execute": False, "benchmark_run": "not_performed", "comparison": "structurally_comparable", "provider": "not_performed", "llm": "not_performed", "network": "disabled", "durable_state": "not_performed", "remote_verification": "unverified"}:
        raise IntegrationError("unsafe terminal projection")
    evidence = _fields(record["evidence"], {"checker", "record_digest", "hostile_cases", "offline_boundary"}, "evidence")
    if evidence["checker"] != "awr-asb-integration-checker/1.0.0" or evidence["hostile_cases"] != ["stale_revision", "crossed_binding", "replayed_operation", "unsupported_agent", "non_identical_configuration", "unacknowledged_cancellation", "provider_execution", "raw_llm_payload", "confounded_comparison"] or evidence["offline_boundary"] != {"provider": "not_performed", "network": "disabled", "llm": "not_performed", "benchmark": "not_performed", "credentials": "references_only", "durable_state": "not_performed", "remote_verification": "unverified"} or evidence["record_digest"] != digest({key: record[key] for key in record if key != "evidence"}):
        raise IntegrationError("evidence boundary or record digest mismatch")
    return {"contract": "awr-asb-integration@1.0.0", "task_revision": 5, "stages": len(trace), "agents": agents, "benchmark_run": "not_performed", "comparison": "structurally_comparable", "execute": False, "provider": "not_performed", "llm": "not_performed", "remote_verification": "unverified"}

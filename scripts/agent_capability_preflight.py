#!/usr/bin/env python3
"""Deterministic, offline AR-0051 capability discovery and preflight model."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-agent-capability-preflight", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
FORBIDDEN = re.compile(r"credential(?!_reference)|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|network.?address|executable", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential|secret)\s*[:=]", re.I)
ALLOWED_SENSITIVE_KEYS = {"credential_reference", "credential_readiness", "credentials"}


class PreflightError(ValueError):
    """Fail-closed AR-0051 violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PreflightError("malformed " + name)
    return value


def _safe(value):
    if isinstance(value, dict):
        return all((str(key) in ALLOWED_SENSITIVE_KEYS or not FORBIDDEN.search(str(key))) and _safe(child) for key, child in value.items())
    if isinstance(value, list):
        return all(_safe(child) for child in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE_VALUE.search(value)))


def _capabilities(values, name):
    if not isinstance(values, list) or not values or len(values) > 32 or len(set(values)) != len(values) or any(not isinstance(item, str) or not CAPABILITY.fullmatch(item) for item in values):
        raise PreflightError("invalid " + name)
    return set(values)


def _status(observation):
    gates = [observation[key] for key in ("catalog_acceptance", "setup_acceptance", "credential_readiness", "host_gate", "network_gate", "capability_support", "benchmark_compatibility")]
    if any(value in {"rejected", "missing", "partial", "invalid", "mismatch", "unsupported", "incompatible"} for value in gates):
        return "not_eligible"
    if any(value in {"unknown"} for value in gates):
        return "unknown"
    return "eligible"


def discover(declaration, expected_revision=5):
    fields = {"task", "agent_id", "adapter_id", "adapter_version", "catalog_acceptance", "declared_capabilities", "supported_capabilities", "model_digest"}
    _object(declaration, fields, "agent declaration")
    if declaration["task"] != {"id": "AR-0051", "revision": expected_revision} or expected_revision != 5:
        raise PreflightError("stale or invalid task binding")
    for key in ("agent_id", "adapter_id"):
        if not isinstance(declaration[key], str) or not IDENTIFIER.fullmatch(declaration[key]):
            raise PreflightError("invalid " + key)
    if not isinstance(declaration["adapter_version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", declaration["adapter_version"]):
        raise PreflightError("invalid adapter version")
    _capabilities(declaration["declared_capabilities"], "declared capabilities")
    _capabilities(declaration["supported_capabilities"], "supported capabilities")
    if declaration["catalog_acceptance"] not in {"accepted", "rejected", "unknown"} or not DIGEST.fullmatch(declaration["model_digest"]):
        raise PreflightError("invalid catalog discovery")
    return {"state": "catalog_accepted" if declaration["catalog_acceptance"] == "accepted" else declaration["catalog_acceptance"], "adapter_id": declaration["adapter_id"], "supported_capabilities": list(declaration["supported_capabilities"])}


def preflight(record, expected_revision=5):
    fields = {"schema_version", "protocol", "task", "agent", "configuration", "preflight", "result", "evidence"}
    _object(record, fields, "preflight record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "AR-0051", "revision": expected_revision} or expected_revision != 5:
        raise PreflightError("unsupported or stale preflight record")
    if not _safe(record):
        raise PreflightError("privacy-bearing preflight record")
    discover(record["agent"], expected_revision)
    configuration = _object(record["configuration"], {"setup_acceptance", "credential_reference", "host_gate", "network_gate", "requested_capabilities", "benchmark_capabilities"}, "configuration")
    if configuration["setup_acceptance"] not in {"accepted", "rejected", "unknown"}:
        raise PreflightError("invalid setup acceptance")
    credentials = _object(configuration["credential_reference"], {"status", "reference_digest", "value_absent"}, "credential reference")
    if credentials["status"] not in {"ready", "missing", "partial", "invalid", "not_required"} or credentials["status"] == "ready" and not DIGEST.fullmatch(credentials["reference_digest"]):
        raise PreflightError("invalid credential readiness")
    if credentials["value_absent"] is not True or (credentials["status"] != "ready" and credentials["reference_digest"] is not None):
        raise PreflightError("credential value or partial reference supplied")
    for gate in ("host_gate", "network_gate"):
        if configuration[gate] not in {"pass", "mismatch", "unknown"}:
            raise PreflightError("invalid " + gate)
    requested = _capabilities(configuration["requested_capabilities"], "requested capabilities")
    benchmark = _capabilities(configuration["benchmark_capabilities"], "benchmark capabilities")
    supported = _capabilities(record["agent"]["supported_capabilities"], "supported capabilities")
    capability_status = "supported" if requested <= supported else "unsupported"
    benchmark_status = "compatible" if benchmark <= supported and benchmark <= requested else "incompatible"
    observation = {"catalog_acceptance": record["agent"]["catalog_acceptance"], "setup_acceptance": configuration["setup_acceptance"], "credential_readiness": credentials["status"], "host_gate": configuration["host_gate"], "network_gate": configuration["network_gate"], "capability_support": capability_status, "benchmark_compatibility": benchmark_status}
    expected = _object(record["preflight"], set(observation) | {"state_before", "state_after", "adapter_execution", "live_support"}, "preflight observation")
    if expected != {**observation, "state_before": "configured", "state_after": _status(observation), "adapter_execution": "not_performed", "live_support": "unverified"}:
        raise PreflightError("preflight state or gate result mismatch")
    result = _object(record["result"], {"status", "benchmark_eligibility", "execute", "provider_support", "live_support", "durable_state"}, "result")
    expected_result = {"status": _status(observation), "benchmark_eligibility": _status(observation), "execute": False, "provider_support": "unverified", "live_support": "unverified", "durable_state": "not_performed"}
    if result != expected_result:
        raise PreflightError("eligibility result is inconsistent")
    evidence = _object(record["evidence"], {"checker", "record_digest", "hostile_cases", "offline_boundary"}, "evidence")
    if evidence["checker"] != "awr-agent-capability-preflight-checker/1.0.0" or evidence["hostile_cases"] != ["missing_credential", "partial_credential", "unsupported_capability", "host_mismatch", "network_mismatch", "provider_unverified"] or evidence["offline_boundary"] != {"provider": "not_performed", "adapter_execution": "not_performed", "network": "disabled", "credentials": "references_only", "live_support": "unverified", "durable_state": "not_performed"}:
        raise PreflightError("hostile or offline evidence is incomplete")
    if evidence["record_digest"] != sha256(canonical_bytes({key: record[key] for key in record if key != "evidence"})):
        raise PreflightError("record digest mismatch")
    return {"task_revision": 5, "state": expected["state_after"], "benchmark_eligibility": expected["state_after"], "adapter_execution": "not_performed", "live_support": "unverified"}

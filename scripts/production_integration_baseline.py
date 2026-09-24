#!/usr/bin/env python3
"""Offline AR-0080 production-integration baseline and admission model."""

import hashlib
import json
import re


PROTOCOL = {"id": "awr-production-integration-baseline", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
MODE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
FORBIDDEN_KEY = re.compile(
    r"credential|password|secret|token|prompt|transcript|private.?path|"
    r"host.?identifier|network.?address|raw.?output|executable",
    re.IGNORECASE,
)
PRIVATE_VALUE = re.compile(
    r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|"
    r"BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential|secret)\s*[:=]",
    re.IGNORECASE,
)


class IntegrationError(ValueError):
    """Fail-closed AR-0080 violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise IntegrationError("malformed " + name)
    return value


def _safe(value):
    if isinstance(value, dict):
        return all(not FORBIDDEN_KEY.search(str(key)) and _safe(child) for key, child in value.items())
    if isinstance(value, list):
        return len(value) <= 64 and all(_safe(child) for child in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE_VALUE.search(value)))


def _list(value, pattern, name, *, unique=True, allow_empty=False):
    if not isinstance(value, list) or (not allow_empty and not value) or len(value) > 32:
        raise IntegrationError("invalid " + name)
    if unique and len(set(value)) != len(value):
        raise IntegrationError("duplicate " + name)
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value):
        raise IntegrationError("invalid " + name)
    return value


def _profiles(spec, name):
    profiles = spec[name]
    if not isinstance(profiles, list) or not profiles:
        raise IntegrationError("invalid " + name)
    result = {}
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("id"), str):
            raise IntegrationError("malformed " + name + " profile")
        if profile["id"] in result:
            raise IntegrationError("duplicate profile")
        result[profile["id"]] = profile
    return result


def validate_spec(spec, expected_revision=1):
    fields = {
        "schema_version", "specification_id", "version", "title", "normative", "task",
        "profiles", "authority_ownership", "failure_classifications", "modes", "matrix", "outcomes", "privacy",
        "offline_boundary", "hostile_qualification", "limitations", "follow_up",
    }
    if not isinstance(spec, dict) or set(spec) != fields:
        raise IntegrationError("malformed specification")
    if (
        spec["schema_version"] != 1
        or spec["specification_id"] != PROTOCOL["id"]
        or spec["version"] != PROTOCOL["version"]
        or spec["normative"] is not True
        or spec["task"] != {"id": "AR-0080", "revision": expected_revision}
        or expected_revision != 1
    ):
        raise IntegrationError("unsupported or stale specification")
    profile_groups = spec["profiles"]
    _object(profile_groups, {"runtime", "hosts", "projects", "agents", "authorities"}, "profile groups")
    runtime = _profiles(profile_groups, "runtime")
    hosts = _profiles(profile_groups, "hosts")
    projects = _profiles(profile_groups, "projects")
    agents = _profiles(profile_groups, "agents")
    authorities = _profiles(profile_groups, "authorities")
    if not all(IDENTIFIER.fullmatch(key) for key in (*runtime, *hosts, *projects, *agents, *authorities)):
        raise IntegrationError("invalid profile identifier")
    for profile in (*runtime.values(), *hosts.values(), *projects.values(), *agents.values(), *authorities.values()):
        if not VERSION.fullmatch(profile["version"]):
            raise IntegrationError("invalid profile version")
    for profile in runtime.values():
        _object(profile, {"id", "version", "features", "contract_versions"}, "runtime profile")
        _list(profile["features"], CAPABILITY, "runtime features")
        _list(profile["contract_versions"], VERSION, "runtime contract versions")
    for profile in hosts.values():
        _object(profile, {"id", "version", "capabilities", "network"}, "host profile")
        _list(profile["capabilities"], CAPABILITY, "host capabilities")
        if profile["network"] not in {"disabled", "observed_only"}:
            raise IntegrationError("unsafe host network mode")
    for profile in projects.values():
        _object(profile, {"id", "version", "authority_profile", "modes"}, "project profile")
        if profile["authority_profile"] not in authorities or not isinstance(profile["modes"], list):
            raise IntegrationError("invalid project profile")
        if not set(profile["modes"]) <= set(spec["modes"]):
            raise IntegrationError("unknown project mode")
    for profile in agents.values():
        _object(profile, {"id", "version", "adapter_id", "adapter_version", "capabilities"}, "agent profile")
        if not IDENTIFIER.fullmatch(profile["adapter_id"]) or not VERSION.fullmatch(profile["adapter_version"]):
            raise IntegrationError("invalid agent adapter version")
        _list(profile["capabilities"], CAPABILITY, "agent capabilities")
    for profile in authorities.values():
        _object(profile, {"id", "version", "owners", "contract_versions"}, "authority profile")
        if not isinstance(profile["owners"], dict) or not profile["owners"]:
            raise IntegrationError("invalid authority owners")
        if any(not IDENTIFIER.fullmatch(key) or not IDENTIFIER.fullmatch(value) for key, value in profile["owners"].items()):
            raise IntegrationError("invalid authority owner")
        if not isinstance(profile["contract_versions"], dict) or set(profile["contract_versions"]) != set(profile["owners"]):
            raise IntegrationError("invalid authority contracts")
        if any(not VERSION.fullmatch(value) for value in profile["contract_versions"].values()):
            raise IntegrationError("invalid authority contract version")
    ownership = spec["authority_ownership"]
    if not isinstance(ownership, dict) or set(ownership) != {"awc", "awr", "awq", "awg"}:
        raise IntegrationError("incomplete authority ownership")
    for authority, declaration in ownership.items():
        _object(declaration, {"owner", "domains", "may_approve"}, authority + " ownership")
        if declaration["owner"] != authority or not isinstance(declaration["may_approve"], bool):
            raise IntegrationError("invalid authority owner")
        _list(declaration["domains"], CAPABILITY, authority + " authority domains")
    classifications = spec["failure_classifications"]
    if not isinstance(classifications, dict) or not classifications:
        raise IntegrationError("missing failure classifications")
    for name, declaration in classifications.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", name):
            raise IntegrationError("invalid failure classification")
        _object(declaration, {"outcome", "authority", "retryable"}, "failure classification")
        if declaration["outcome"] not in {"admitted", "degraded", "blocked", "pending", "unknown"} or declaration["authority"] not in {"awc", "awr", "awq", "awg"} or not isinstance(declaration["retryable"], bool):
            raise IntegrationError("invalid failure classification")
    if not isinstance(spec["modes"], dict) or not spec["modes"]:
        raise IntegrationError("invalid integration modes")
    for mode, declaration in spec["modes"].items():
        if not isinstance(mode, str) or not MODE.fullmatch(mode):
            raise IntegrationError("invalid mode")
        _object(declaration, {"host_profile", "execution", "qualification", "remote_support"}, "mode")
        if declaration["host_profile"] not in hosts:
            raise IntegrationError("mode references unknown host")
        if declaration["execution"] != "not_performed" or declaration["qualification"] not in {"synthetic", "supplied_only"}:
            raise IntegrationError("unsafe mode boundary")
        if declaration["remote_support"] not in {"unverified", "not_applicable"}:
            raise IntegrationError("unsafe remote support")
    rows = spec["matrix"]
    if not isinstance(rows, list) or not rows:
        raise IntegrationError("empty compatibility matrix")
    row_ids = set()
    keys = {"id", "runtime_profile", "host_profile", "project_class", "agent_profile", "authority_profile", "mode", "status", "reason"}
    valid_status = {"compatible", "degraded", "unsupported"}
    for row in rows:
        _object(row, keys, "matrix row")
        if row["id"] in row_ids or not IDENTIFIER.fullmatch(row["id"]):
            raise IntegrationError("duplicate or invalid matrix row")
        row_ids.add(row["id"])
        if row["runtime_profile"] not in runtime or row["host_profile"] not in hosts or row["project_class"] not in projects or row["agent_profile"] not in agents or row["authority_profile"] not in authorities or row["mode"] not in spec["modes"]:
            raise IntegrationError("matrix references unknown profile")
        if row["status"] not in valid_status or not isinstance(row["reason"], str) or not row["reason"]:
            raise IntegrationError("invalid matrix result")
        if spec["modes"][row["mode"]]["host_profile"] != row["host_profile"]:
            raise IntegrationError("matrix mode and host mismatch")
        if projects[row["project_class"]]["authority_profile"] != row["authority_profile"]:
            raise IntegrationError("matrix project and authority mismatch")
    if not isinstance(spec["outcomes"], dict) or set(spec["outcomes"]) != {"admitted", "degraded", "blocked"}:
        raise IntegrationError("incomplete outcomes")
    if not isinstance(spec["hostile_qualification"], list) or not spec["hostile_qualification"] or not isinstance(spec["follow_up"], list) or not spec["follow_up"]:
        raise IntegrationError("incomplete qualification or follow-up")
    return {"runtime": runtime, "hosts": hosts, "projects": projects, "agents": agents, "authorities": authorities}


def _row(spec, selection):
    for row in spec["matrix"]:
        if all(row[key] == selection[key] for key in ("runtime_profile", "host_profile", "project_class", "agent_profile", "authority_profile", "mode")):
            return row
    return None


def validate(record, spec, expected_revision=1):
    profiles = validate_spec(spec, expected_revision)
    fields = {"schema_version", "protocol", "task", "selection", "authority_snapshot", "version_negotiation", "observation", "result", "evidence"}
    _object(record, fields, "integration record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "AR-0080", "revision": expected_revision}:
        raise IntegrationError("unsupported or stale integration record")
    if not _safe(record):
        raise IntegrationError("privacy-bearing integration record")
    selection = _object(record["selection"], {"runtime_profile", "host_profile", "project_class", "agent_profile", "authority_profile", "mode", "requested_capabilities"}, "selection")
    for key, group in (("runtime_profile", "runtime"), ("host_profile", "hosts"), ("project_class", "projects"), ("agent_profile", "agents"), ("authority_profile", "authorities")):
        if selection[key] not in profiles[group]:
            raise IntegrationError("unknown " + key)
    _list(selection["requested_capabilities"], CAPABILITY, "requested capabilities")
    authority = profiles["authorities"][selection["authority_profile"]]
    snapshot = _object(record["authority_snapshot"], {"profile_id", "owners", "contract_versions"}, "authority snapshot")
    if snapshot != {"profile_id": authority["id"], "owners": authority["owners"], "contract_versions": authority["contract_versions"]}:
        raise IntegrationError("authority ownership mismatch")
    negotiation = _object(record["version_negotiation"], {"runtime_version", "adapter_version"}, "version negotiation")
    if not VERSION.fullmatch(negotiation["runtime_version"]) or not VERSION.fullmatch(negotiation["adapter_version"]):
        raise IntegrationError("invalid negotiated version")
    runtime = profiles["runtime"][selection["runtime_profile"]]
    agent = profiles["agents"][selection["agent_profile"]]
    project = profiles["projects"][selection["project_class"]]
    mode = spec["modes"].get(selection["mode"])
    row = _row(spec, selection)
    reason = None
    if negotiation["runtime_version"] != runtime["version"] or negotiation["adapter_version"] != agent["adapter_version"]:
        reason = "incompatible_version"
    elif selection["mode"] not in project["modes"] or mode is None:
        reason = "unsupported_mode"
    elif set(selection["requested_capabilities"]) - set(agent["capabilities"]):
        reason = "unsupported_capability"
    elif row is None or row["status"] == "unsupported":
        reason = "unsupported_combination"
    elif row["status"] == "degraded":
        reason = "degraded_combination"
    else:
        reason = "compatible"
    matrix_status = row["status"] if row is not None else "unknown"
    expected_observation = {
        "matrix_status": matrix_status,
        "matched_row": row["id"] if row is not None else None,
        "version_status": "compatible" if reason != "incompatible_version" else "incompatible",
        "capability_status": "supported" if reason != "unsupported_capability" else "unsupported",
        "authority_status": "owned",
    }
    if record["observation"] != expected_observation:
        raise IntegrationError("inconsistent compatibility observation")
    status = {"compatible": "admitted", "degraded_combination": "degraded"}.get(reason, "blocked")
    result = _object(record["result"], {"status", "admission", "classification", "execute", "qualification", "provider_support", "remote_verification", "durable_state"}, "integration result")
    expected_result = {
        "status": status,
        "admission": status == "admitted",
        "classification": reason,
        "execute": False,
        "qualification": "synthetic" if mode and mode["qualification"] == "synthetic" else "supplied_only",
        "provider_support": "unverified",
        "remote_verification": "unverified",
        "durable_state": "not_performed",
    }
    if result != expected_result:
        raise IntegrationError("inconsistent admission result")
    evidence = _object(record["evidence"], {"checker", "specification_digest", "record_digest", "hostile_cases", "offline_boundary"}, "integration evidence")
    if evidence["checker"] != "awr-production-integration-baseline-checker/1.0.0" or evidence["specification_digest"] != digest(canonical_bytes(spec)):
        raise IntegrationError("evidence binding mismatch")
    if evidence["hostile_cases"] != ["unknown_capability", "unknown_runtime_version", "unknown_adapter_version", "crossed_revision", "crossed_authority", "unsupported_combination", "provider_claim_without_evidence"]:
        raise IntegrationError("hostile evidence incomplete")
    if evidence["offline_boundary"] != {"provider": "not_performed", "network": "disabled", "llm": "not_performed", "adapter_execution": "not_performed", "local_host_execution": "not_performed", "durable_state": "not_performed", "remote_verification": "unverified"}:
        raise IntegrationError("unsafe offline boundary")
    if reason not in spec["failure_classifications"]:
        raise IntegrationError("unclassified admission result")
    expected_record_digest = digest(canonical_bytes({key: record[key] for key in record if key != "evidence"}))
    if evidence["record_digest"] != expected_record_digest:
        raise IntegrationError("record digest mismatch")
    return {"task_revision": expected_revision, "status": status, "classification": reason, "admission": status == "admitted", "execute": False, "provider_support": "unverified"}

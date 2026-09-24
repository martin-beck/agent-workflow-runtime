#!/usr/bin/env python3
"""AR-0084 versioned agent registry and fail-closed preflight model.

This module evaluates supplied, digest-bound declarations only.  It never
discovers a provider, starts an adapter, opens a network connection, invokes an
LLM, or mutates durable state.
"""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-agent-registry", "version": "1.0.0"}
TASK = {"id": "AR-0084", "revision": 3}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CONFIG_REFERENCE = re.compile(r"^config:[a-z][a-z0-9-]{2,63}:v[0-9]+$")
FORBIDDEN_KEY = re.compile(
    r"credential(?!_reference)|password|secret|token|prompt|transcript|"
    r"private.?path|host.?identifier|network.?address|raw.?output|executable",
    re.IGNORECASE,
)
PRIVATE_VALUE = re.compile(
    r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|"
    r"BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential|secret)\s*[:=]",
    re.IGNORECASE,
)


class RegistryError(ValueError):
    """Fail-closed AR-0084 violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise RegistryError("malformed " + name)
    return value


def _safe(value):
    if isinstance(value, dict):
        return all(not FORBIDDEN_KEY.search(str(key)) and _safe(child) for key, child in value.items())
    if isinstance(value, list):
        return len(value) <= 64 and all(_safe(child) for child in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE_VALUE.search(value)))


def _list(value, pattern, name, *, allow_empty=False):
    if not isinstance(value, list) or len(value) > 32 or (not allow_empty and not value):
        raise RegistryError("invalid " + name)
    if len(set(value)) != len(value) or any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value):
        raise RegistryError("invalid " + name)
    return value


def _digest_without(value, field):
    return sha256(canonical_bytes({key: child for key, child in value.items() if key != field}))


def _profile(profile):
    fields = {
        "id", "version", "adapter_id", "adapter_version", "protocol_versions",
        "capabilities", "resources", "configuration_reference", "unsupported_capabilities",
        "profile_digest",
    }
    _object(profile, fields, "agent profile")
    if not IDENTIFIER.fullmatch(profile["id"]) or not VERSION.fullmatch(profile["version"]):
        raise RegistryError("invalid profile identity")
    if not IDENTIFIER.fullmatch(profile["adapter_id"]) or not VERSION.fullmatch(profile["adapter_version"]):
        raise RegistryError("invalid adapter identity")
    if not isinstance(profile["protocol_versions"], list) or not profile["protocol_versions"] or any(not VERSION.fullmatch(item) for item in profile["protocol_versions"]):
        raise RegistryError("invalid protocol versions")
    _list(profile["capabilities"], CAPABILITY, "capabilities")
    _list(profile["unsupported_capabilities"], CAPABILITY, "unsupported capabilities", allow_empty=True)
    if set(profile["capabilities"]) & set(profile["unsupported_capabilities"]):
        raise RegistryError("contradictory capability declaration")
    resources = _object(profile["resources"], {"max_concurrency", "max_request_bytes", "max_output_events"}, "resources")
    if any(not isinstance(resources[key], int) or resources[key] < 1 or resources[key] > 65536 for key in resources):
        raise RegistryError("invalid resource declaration")
    if not CONFIG_REFERENCE.fullmatch(str(profile["configuration_reference"])):
        raise RegistryError("invalid configuration reference")
    if not DIGEST.fullmatch(str(profile["profile_digest"])) or profile["profile_digest"] != _digest_without(profile, "profile_digest"):
        raise RegistryError("profile digest mismatch")
    return profile


def validate_spec(spec, expected_revision=3):
    fields = {
        "schema_version", "specification_id", "version", "title", "normative", "task",
        "registry_version", "capability_vocabulary", "profiles", "qualification_modes",
        "outcomes", "privacy", "offline_boundary", "hostile_qualification", "limitations",
    }
    if not isinstance(spec, dict) or set(spec) != fields:
        raise RegistryError("malformed registry specification")
    if (
        spec["schema_version"] != 1
        or spec["specification_id"] != PROTOCOL["id"]
        or spec["version"] != PROTOCOL["version"]
        or spec["normative"] is not True
        or spec["task"] != {"id": TASK["id"], "revision": expected_revision}
        or expected_revision != TASK["revision"]
        or not VERSION.fullmatch(spec["registry_version"])
    ):
        raise RegistryError("unsupported or stale registry specification")
    _list(spec["capability_vocabulary"], CAPABILITY, "capability vocabulary")
    vocabulary = set(spec["capability_vocabulary"])
    profiles = spec["profiles"]
    if not isinstance(profiles, list) or len(profiles) != 4:
        raise RegistryError("registry must contain four profiles")
    by_id = {}
    for profile in profiles:
        _profile(profile)
        if profile["id"] in by_id:
            raise RegistryError("duplicate profile identity")
        if not set(profile["capabilities"]) <= vocabulary or not set(profile["unsupported_capabilities"]) <= vocabulary:
            raise RegistryError("profile uses unknown capability")
        by_id[profile["id"]] = profile
    if set(by_id) != {"codex-agent", "opencode-agent", "opendesk-agent", "generic-mock-agent"}:
        raise RegistryError("incomplete required profile set")
    modes = spec["qualification_modes"]
    _object(modes, {"catalog", "configuration", "local_mock", "provider"}, "qualification modes")
    if modes != {
        "catalog": {"accepted": "profile is present in this exact registry digest"},
        "configuration": {"accepted": "configuration reference is present and structurally valid"},
        "local_mock": {"accepted": "deterministic fake qualification evidence is supplied"},
        "provider": {"accepted": "never inferred; separately supplied evidence is required"},
    }:
        raise RegistryError("qualification mode semantics changed")
    if not isinstance(spec["outcomes"], dict) or set(spec["outcomes"]) != {"admitted", "blocked", "unknown"}:
        raise RegistryError("incomplete preflight outcomes")
    if not isinstance(spec["hostile_qualification"], list) or not spec["hostile_qualification"]:
        raise RegistryError("missing hostile qualification cases")
    if not isinstance(spec["limitations"], list) or not spec["limitations"]:
        raise RegistryError("missing limitations")
    if spec["offline_boundary"] != {
        "provider": "not_performed", "network": "disabled", "llm": "not_performed",
        "adapter_execution": "not_performed", "local_mock": "deterministic_fake_only",
        "durable_state": "not_performed", "remote_verification": "unverified",
    }:
        raise RegistryError("unsafe offline boundary")
    return by_id


class AgentRegistry:
    """In-memory registry over one already-loaded, validated specification."""

    def __init__(self, spec, expected_revision=3):
        self.spec = spec
        self.profiles = validate_spec(spec, expected_revision)
        self.registry_digest = sha256(canonical_bytes(spec))

    def profile(self, profile_id):
        try:
            return self.profiles[profile_id]
        except KeyError as exc:
            raise RegistryError("unknown agent profile") from exc

    def negotiate(self, request):
        fields = {"profile_id", "profile_version", "adapter_version", "protocol_version", "requested_capabilities"}
        _object(request, fields, "capability request")
        profile = self.profile(request["profile_id"])
        if request["profile_version"] != profile["version"] or request["adapter_version"] != profile["adapter_version"]:
            raise RegistryError("stale profile or adapter version")
        if request["protocol_version"] not in profile["protocol_versions"]:
            raise RegistryError("unsupported protocol version")
        requested = _list(request["requested_capabilities"], CAPABILITY, "requested capabilities")
        unsupported = sorted(set(requested) - set(profile["capabilities"]))
        return {
            "catalog_status": "accepted",
            "profile_digest": profile["profile_digest"],
            "protocol_status": "supported",
            "capability_status": "supported" if not unsupported else "unsupported",
            "selected_capabilities": sorted(set(requested) - set(unsupported)),
            "unsupported_capabilities": unsupported,
        }

    def preflight(self, record, expected_revision=3):
        return preflight(record, self.spec, expected_revision)


def _qualification_evidence(profile_id):
    return sha256(canonical_bytes({"profile_id": profile_id, "mode": "local_mock", "qualification": "qualified", "execution": "deterministic_fake"}))


def preflight(record, spec, expected_revision=3):
    profiles = validate_spec(spec, expected_revision)
    fields = {"schema_version", "protocol", "task", "registry_digest", "request", "configuration", "qualification", "negotiation", "result", "evidence"}
    _object(record, fields, "preflight record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": TASK["id"], "revision": expected_revision}:
        raise RegistryError("unsupported or stale preflight record")
    if not _safe(record):
        raise RegistryError("privacy-bearing preflight record")
    if record["registry_digest"] != sha256(canonical_bytes(spec)):
        raise RegistryError("registry digest mismatch")
    request = _object(record["request"], {"profile_id", "profile_version", "adapter_version", "protocol_version", "requested_capabilities"}, "capability request")
    profile = profiles.get(request["profile_id"])
    if profile is None:
        raise RegistryError("unknown agent profile")
    negotiated = AgentRegistry(spec, expected_revision).negotiate(request)
    configuration = _object(record["configuration"], {"status", "reference", "reference_digest", "value_absent"}, "configuration")
    if configuration["status"] not in {"accepted", "rejected", "unknown"} or not CONFIG_REFERENCE.fullmatch(str(configuration["reference"])):
        raise RegistryError("invalid configuration acceptance")
    if configuration["status"] == "accepted" and (not DIGEST.fullmatch(str(configuration["reference_digest"])) or configuration["value_absent"] is not True):
        raise RegistryError("accepted configuration must be reference-only")
    if configuration["status"] != "accepted" and configuration["reference_digest"] is not None:
        raise RegistryError("rejected configuration cannot carry a digest")
    if configuration["value_absent"] is not True:
        raise RegistryError("configuration value must be absent")
    qualification = _object(record["qualification"], {"local_mock", "provider"}, "qualification")
    local = _object(qualification["local_mock"], {"status", "evidence_digest", "execution"}, "local mock qualification")
    provider = _object(qualification["provider"], {"status", "evidence_digest", "execution"}, "provider verification")
    if local["status"] != "qualified" or local["execution"] != "deterministic_fake" or local["evidence_digest"] != _qualification_evidence(profile["id"]):
        raise RegistryError("missing or contradictory local mock qualification")
    if provider["status"] != "unverified" or provider["evidence_digest"] is not None or provider["execution"] != "not_performed":
        raise RegistryError("provider verification cannot be claimed by offline preflight")
    negotiation = _object(record["negotiation"], {"catalog_status", "profile_digest", "protocol_status", "capability_status", "selected_capabilities", "unsupported_capabilities"}, "negotiation")
    if negotiation != negotiated:
        raise RegistryError("capability negotiation is inconsistent")
    if configuration["status"] != "accepted":
        classification = "configuration_unavailable"
    elif negotiated["capability_status"] != "supported":
        classification = "unsupported_capability"
    else:
        classification = "compatible"
    status = "admitted" if classification == "compatible" else "blocked"
    result = _object(record["result"], {"status", "admission", "classification", "execute", "catalog_acceptance", "configuration_acceptance", "local_mock_qualification", "provider_verification", "provider_support", "remote_verification", "durable_state"}, "result")
    expected_result = {
        "status": status, "admission": status == "admitted", "classification": classification,
        "execute": False, "catalog_acceptance": "accepted", "configuration_acceptance": configuration["status"],
        "local_mock_qualification": "qualified", "provider_verification": "unverified", "provider_support": "unverified",
        "remote_verification": "unverified", "durable_state": "not_performed",
    }
    if result != expected_result:
        raise RegistryError("preflight result is inconsistent")
    evidence = _object(record["evidence"], {"checker", "registry_digest", "record_digest", "hostile_cases", "offline_boundary"}, "evidence")
    if evidence["checker"] != "awr-agent-registry-checker/1.0.0" or evidence["registry_digest"] != record["registry_digest"]:
        raise RegistryError("evidence binding mismatch")
    if evidence["hostile_cases"] != ["unknown_profile", "stale_profile", "unsupported_capability", "missing_configuration", "contradictory_qualification", "provider_claim_without_execution", "crossed_revision"]:
        raise RegistryError("hostile evidence incomplete")
    if evidence["offline_boundary"] != spec["offline_boundary"]:
        raise RegistryError("unsafe evidence boundary")
    expected_digest = sha256(canonical_bytes({key: value for key, value in record.items() if key != "evidence"}))
    if evidence["record_digest"] != expected_digest:
        raise RegistryError("record digest mismatch")
    return {"task_revision": expected_revision, "profile_id": profile["id"], "status": status, "classification": classification, "admission": status == "admitted", "execute": False, "provider_verification": "unverified"}

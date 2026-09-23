"""Deterministic offline model for the AR-0049 provider security boundary."""

import hashlib
import json
import re
from urllib.parse import urlsplit


class ProviderSecurityError(ValueError):
    pass


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
IDENT = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,63}$")
SECRET_MANAGER = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
SECRET_NAME = re.compile(r"^[a-z][a-z0-9._/-]{1,127}$")
HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$")
PRIVATE = re.compile(r"(?:password|secret_value|token_value|credential_value|prompt|transcript|raw_output|private_path|host_identifier)", re.I)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value, label):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ProviderSecurityError("invalid " + label)


def _object(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ProviderSecurityError("malformed " + label)
    return value


def _private(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)) and str(key) not in {"secret_values_absent"}:
                return True
            if _private(child):
                return True
    elif isinstance(value, list):
        return any(_private(child) for child in value)
    elif isinstance(value, str):
        return bool(re.search(r"BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|(?:password|token|secret)\s*[:=]", value, re.I))
    return False


def _bounded_int(value, label, minimum=0):
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ProviderSecurityError("invalid " + label)


def validate_secret_reference(reference):
    reference = _object(reference, {"manager", "name", "version", "digest"}, "secret reference")
    if not SECRET_MANAGER.fullmatch(str(reference["manager"])) or not SECRET_NAME.fullmatch(str(reference["name"])):
        raise ProviderSecurityError("invalid secret-manager reference")
    _bounded_int(reference["version"], "secret version", 1)
    _digest(reference["digest"], "secret reference digest")
    return reference


def validate_destination(destination):
    destination = _object(destination, {"url", "tls", "network", "max_connections"}, "destination")
    if not isinstance(destination["url"], str) or len(destination["url"]) > 256:
        raise ProviderSecurityError("destination URL is unbounded")
    parsed = urlsplit(destination["url"])
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port != 443:
        raise ProviderSecurityError("destination must be an HTTPS port-443 endpoint")
    if not parsed.hostname or not HOST.fullmatch(parsed.hostname) or parsed.hostname in {"localhost", "127.0.0.1", "::1"} or "." not in parsed.hostname:
        raise ProviderSecurityError("destination host is not an approved public name")
    if destination["tls"] != {"required": True, "min_version": "1.3", "verify_peer": True} or destination["network"] != "egress_allowlist":
        raise ProviderSecurityError("unsafe TLS or network policy")
    _bounded_int(destination["max_connections"], "connection bound", 1)
    if destination["max_connections"] > 2:
        raise ProviderSecurityError("connection bound exceeded")
    return destination


def _validate_injection(injection, references):
    injection = _object(injection, {"mode", "target", "reference_digest", "value_present", "lifetime_ms", "cleanup"}, "injection")
    if injection["mode"] != "ephemeral" or not NAME.fullmatch(str(injection["target"])) or injection["value_present"] is not False or injection["cleanup"] != "on_completion_or_cancel":
        raise ProviderSecurityError("credential injection is not ephemeral")
    _digest(injection["reference_digest"], "injection reference digest")
    _bounded_int(injection["lifetime_ms"], "injection lifetime", 1)
    if injection["lifetime_ms"] > 30000 or injection["reference_digest"] not in {ref["digest"] for ref in references}:
        raise ProviderSecurityError("injection is not bounded to a supplied reference")


def _validate_policy(policy):
    policy = _object(policy, {"request_bytes", "response_bytes", "frame_bytes", "frame_count", "timeout_ms", "idle_timeout_ms", "cancel_grace_ms", "stream_window"}, "budget policy")
    for key in policy:
        _bounded_int(policy[key], key, 1)
    if policy != {"request_bytes": 4096, "response_bytes": 16384, "frame_bytes": 2048, "frame_count": 16, "timeout_ms": 30000, "idle_timeout_ms": 5000, "cancel_grace_ms": 1000, "stream_window": 4}:
        raise ProviderSecurityError("unsupported or unsafe provider budget")


def _validate_operation(operation, policy, destinations):
    operation = _object(operation, {"id", "kind", "destination", "request_digest", "request_bytes", "attempt", "response", "cancellation"}, "provider operation")
    if not IDENT.fullmatch(str(operation["id"])) or operation["kind"] not in {"request", "retry", "duplicate", "denied_destination", "oversized_request", "missing_credential", "expired_credential"}:
        raise ProviderSecurityError("unknown operation")
    _digest(operation["request_digest"], "request digest")
    _bounded_int(operation["request_bytes"], "request size")
    _bounded_int(operation["attempt"], "attempt", 1)
    if operation["destination"] not in destinations:
        raise ProviderSecurityError("operation uses an undeclared destination")
    response = _object(operation["response"], {"status", "frames", "frames_seen", "bytes", "outcome", "redacted", "evidence_digest"}, "provider response")
    if response["status"] not in {"accepted", "rejected", "cancelled", "unknown"} or response["outcome"] not in {"complete", "partial_failure", "denied", "oversized", "interrupted", "duplicate", "missing_credential", "expired_credential", "unknown"} or response["redacted"] is not True:
        raise ProviderSecurityError("invalid provider outcome")
    _bounded_int(response["frames_seen"], "frames seen")
    _bounded_int(response["bytes"], "response bytes")
    if not isinstance(response["frames"], list) or len(response["frames"]) != response["frames_seen"]:
        raise ProviderSecurityError("frame count mismatch")
    for frame in response["frames"]:
        frame = _object(frame, {"sequence", "bytes", "digest", "redacted"}, "stream frame")
        _bounded_int(frame["sequence"], "frame sequence", 1); _bounded_int(frame["bytes"], "frame bytes")
        _digest(frame["digest"], "frame digest")
        if frame["redacted"] is not True or (frame["bytes"] > policy["frame_bytes"] and response["outcome"] != "oversized"):
            raise ProviderSecurityError("unbounded or unredacted stream frame")
    _digest(response["evidence_digest"], "response evidence digest")
    cancellation = _object(operation["cancellation"], {"requested", "acknowledged", "terminated_within_ms"}, "cancellation")
    if not isinstance(cancellation["requested"], bool) or not isinstance(cancellation["acknowledged"], bool):
        raise ProviderSecurityError("invalid cancellation observation")
    _bounded_int(cancellation["terminated_within_ms"], "cancellation bound")
    if cancellation["requested"] and (not cancellation["acknowledged"] or cancellation["terminated_within_ms"] > policy["cancel_grace_ms"]):
        raise ProviderSecurityError("cancellation was not bounded")
    if (operation["request_bytes"] > policy["request_bytes"] or response["bytes"] > policy["response_bytes"] or response["frames_seen"] > policy["frame_count"]) and response["outcome"] != "oversized":
        raise ProviderSecurityError("transport budget exceeded without rejection")
    if operation["kind"] == "oversized_request" and response["outcome"] != "oversized":
        raise ProviderSecurityError("oversized request was not rejected")
    if operation["kind"] == "duplicate" and response["outcome"] != "duplicate":
        raise ProviderSecurityError("duplicate request was not rejected")
    if operation["kind"] == "denied_destination" and response["outcome"] != "denied":
        raise ProviderSecurityError("denied destination was not rejected")
    if operation["kind"] in {"missing_credential", "expired_credential"} and response["outcome"] != operation["kind"]:
        raise ProviderSecurityError("credential failure was not classified")
    return operation


def validate(record, expected_revision=5):
    fields = {"schema_version", "protocol", "task", "project", "worktree", "session", "references", "injections", "destinations", "policy", "operations", "redaction", "execution", "evidence"}
    if not isinstance(record, dict) or set(record) != fields or _private(record):
        raise ProviderSecurityError("malformed or privacy-bearing provider envelope")
    if record["schema_version"] != 1 or record["protocol"] != {"id": "awr-provider-execution-security", "version": "1.0.0"} or record["task"] != {"id": "AR-0049", "revision": expected_revision} or expected_revision != 5:
        raise ProviderSecurityError("stale or unsupported provider contract")
    project = _object(record["project"], {"key", "revision"}, "project"); worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if project["key"] != "agent-workflow-runtime" or worktree["key"] != "agent-workflow-runtime-0049":
        raise ProviderSecurityError("crossed project or worktree")
    _digest(project["revision"], "project revision"); _digest(worktree["digest"], "worktree digest")
    if not IDENT.fullmatch(str(record["session"])):
        raise ProviderSecurityError("invalid session")
    if not isinstance(record["references"], list) or not record["references"] or len(record["references"]) > 8:
        raise ProviderSecurityError("invalid reference set")
    references = [validate_secret_reference(ref) for ref in record["references"]]
    if len({ref["digest"] for ref in references}) != len(references):
        raise ProviderSecurityError("duplicate secret reference")
    if not isinstance(record["injections"], list) or len(record["injections"]) != len(references):
        raise ProviderSecurityError("injection/reference mismatch")
    for injection in record["injections"]: _validate_injection(injection, references)
    destinations = []
    for destination in record["destinations"]:
        destination = validate_destination(destination)
        if destination["url"] in destinations: raise ProviderSecurityError("duplicate destination")
        destinations.append(destination["url"])
    _validate_policy(record["policy"])
    if not isinstance(record["operations"], list) or not record["operations"] or len(record["operations"]) > 32:
        raise ProviderSecurityError("invalid operation trace")
    seen = set(); attempts = {}
    for operation in record["operations"]:
        operation = _validate_operation(operation, record["policy"], destinations)
        if operation["id"] in seen: raise ProviderSecurityError("duplicate operation")
        seen.add(operation["id"])
        key = operation["request_digest"]
        if operation["kind"] == "retry":
            if key not in attempts or operation["attempt"] <= attempts[key]: raise ProviderSecurityError("invalid retry")
        if operation["kind"] == "request": attempts[key] = operation["attempt"]
    redaction = _object(record["redaction"], {"mode", "secret_values_absent", "raw_frames_absent", "projection", "unknown_outcome"}, "redaction")
    if redaction != {"mode": "digest_only", "secret_values_absent": True, "raw_frames_absent": True, "projection": "bounded_status_codes_frame_digests", "unknown_outcome": "fail_closed_unverified"}:
        raise ProviderSecurityError("unsafe redaction policy")
    if record["execution"] != {"mode": "offline_fixture", "provider": "not_performed", "network": "disabled", "llm": "not_performed", "credentials": "references_only", "live_verification": "unverified"}:
        raise ProviderSecurityError("external provider execution claimed")
    evidence = _object(record["evidence"], {"checker", "record_digest", "operation_count", "unknown_outcome_count", "live_verification"}, "evidence")
    if evidence["checker"] != "awr-provider-execution-security-checker/1.0.0" or evidence["operation_count"] != len(record["operations"]) or evidence["unknown_outcome_count"] != sum(op["response"]["outcome"] == "unknown" for op in record["operations"]) or evidence["live_verification"] != "unverified":
        raise ProviderSecurityError("evidence mismatch")
    unsigned = dict(record); unsigned.pop("evidence")
    if evidence["record_digest"] != sha256(canonical_bytes(unsigned)):
        raise ProviderSecurityError("record digest mismatch")
    return {"contract": "awr-provider-execution-security@1.0.0", "task_revision": 5, "operations": len(seen), "unknown_outcomes": evidence["unknown_outcome_count"], "live_verification": "unverified"}

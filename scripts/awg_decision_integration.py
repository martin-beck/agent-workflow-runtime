#!/usr/bin/env python3
"""Deterministic offline model for AR-0053 AWG decision integration."""

import hashlib
import json
import re

PROTOCOL = {"id": "awr-awg-decision-integration", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^(?:AR|ALT|DEC|GUIDE|REQ|BATCH|SES|EVID|OP)-[A-Z0-9-]{1,63}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|authorization|cookie)", re.I)


class DecisionError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def fields(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise DecisionError("malformed " + name)
    return value


def safe(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or safe(v) for k, v in value.items())
    if isinstance(value, list):
        return any(safe(v) for v in value)
    return isinstance(value, str) and bool(PRIVATE.search(value))


def binding(record):
    return {key: record[key] for key in ("task", "project", "worktree", "session", "request")}


def validate(record, expected_revision=5):
    top = {"protocol", "task", "project", "worktree", "session", "escalation", "request", "transport", "alternatives", "response", "consumption"}
    fields(record, top, "record")
    if record["protocol"] != PROTOCOL:
        raise DecisionError("unsupported protocol")
    if record["task"] != {"id": "AR-0053", "revision": expected_revision}:
        raise DecisionError("stale task revision")
    project = fields(record["project"], {"key", "revision"}, "project")
    worktree = fields(record["worktree"], {"key", "digest"}, "worktree")
    session = fields(record["session"], {"id"}, "session")
    if project["key"] != "agent-workflow-runtime" or not DIGEST.fullmatch(project["revision"]):
        raise DecisionError("invalid project binding")
    if worktree["key"] != "agent-workflow-runtime-0053" or not DIGEST.fullmatch(worktree["digest"]):
        raise DecisionError("invalid worktree binding")
    if not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", session["id"]):
        raise DecisionError("invalid session binding")
    escalation = fields(record["escalation"], {"status", "reason", "context_digest", "batch_id"}, "escalation")
    if escalation["status"] != "required" or escalation["reason"] != "material_alternative" or not DIGEST.fullmatch(escalation["context_digest"]):
        raise DecisionError("invalid escalation")
    if not ID.fullmatch(escalation["batch_id"]) or not escalation["batch_id"].startswith("BATCH-"):
        raise DecisionError("invalid batch id")
    request = fields(record["request"], {"id", "batch_id", "attempt", "input_digest", "binding_digest"}, "request")
    if not ID.fullmatch(request["id"]) or not request["id"].startswith("REQ-") or request["batch_id"] != escalation["batch_id"] or request["attempt"] != 1 or not DIGEST.fullmatch(request["input_digest"]):
        raise DecisionError("invalid decision request")
    if request["binding_digest"] != digest({key: record[key] for key in ("task", "project", "worktree", "session")}):
        raise DecisionError("request binding mismatch")
    transport = fields(record["transport"], {"operation_id", "state", "network", "checkpoint_digest", "interrupted"}, "transport")
    if not ID.fullmatch(transport["operation_id"]) or not transport["operation_id"].startswith("OP-") or transport["state"] != "interrupted" or transport["network"] != "not_performed" or not DIGEST.fullmatch(transport["checkpoint_digest"]) or transport["interrupted"] is not True:
        raise DecisionError("unsafe interrupted transport")
    alternatives = record["alternatives"]
    if not isinstance(alternatives, list) or not 1 <= len(alternatives) <= 8:
        raise DecisionError("invalid alternatives")
    alternative_ids, alternative_digests = set(), set()
    for item in alternatives:
        fields(item, {"id", "evidence_digest"}, "alternative")
        if not ID.fullmatch(item["id"]) or not item["id"].startswith("ALT-") or item["id"] in alternative_ids or not DIGEST.fullmatch(item["evidence_digest"]) or item["evidence_digest"] in alternative_digests:
            raise DecisionError("duplicate or invalid alternative")
        alternative_ids.add(item["id"]); alternative_digests.add(item["evidence_digest"])
    response = fields(record["response"], {"id", "batch_id", "request_id", "source", "status", "decision_status", "decision_digest", "selected_alternative_id", "guidance", "expires_at", "observed_at", "binding_digest"}, "response")
    if not ID.fullmatch(response["id"]) or not response["id"].startswith("DEC-") or response["batch_id"] != escalation["batch_id"] or response["request_id"] != request["id"] or response["source"] != "awg" or response["status"] not in {"received", "not_received"} or response["decision_status"] not in {"not_decided", "decided", "rejected", "conflicting", "expired"}:
        raise DecisionError("invalid AWG response")
    if not isinstance(response["expires_at"], int) or not isinstance(response["observed_at"], int) or response["expires_at"] < 0 or response["observed_at"] < 0:
        raise DecisionError("invalid expiry")
    if response["binding_digest"] != digest(binding(record)):
        raise DecisionError("decision binding mismatch")
    if response["decision_status"] == "decided":
        if response["status"] != "received" or not DIGEST.fullmatch(response["decision_digest"] or "") or response["selected_alternative_id"] not in alternative_ids:
            raise DecisionError("incomplete AWG decision")
    elif response["decision_status"] in {"not_decided", "rejected", "conflicting", "expired"}:
        if response["selected_alternative_id"] is not None or response["decision_digest"] is not None:
            raise DecisionError("runtime or unresolved decision injection")
    guidance = response["guidance"]
    if not isinstance(guidance, list) or len(guidance) > 8:
        raise DecisionError("invalid guidance references")
    seen = set()
    for item in guidance:
        fields(item, {"id", "digest"}, "guidance reference")
        if not ID.fullmatch(item["id"]) or not item["id"].startswith("GUIDE-") or item["id"] in seen or not DIGEST.fullmatch(item["digest"]):
            raise DecisionError("invalid guidance reference")
        seen.add(item["id"])
    consumption = fields(record["consumption"], {"status", "decision_digest", "guidance_digests", "selected_alternative_id", "binding_digest"}, "consumption")
    expected_status = "applied" if response["decision_status"] == "decided" and response["observed_at"] < response["expires_at"] else "blocked_unresolved"
    if consumption["status"] != expected_status or consumption["binding_digest"] != response["binding_digest"]:
        raise DecisionError("incorrect unresolved blocking")
    if expected_status == "applied":
        if consumption["decision_digest"] != response["decision_digest"] or consumption["selected_alternative_id"] != response["selected_alternative_id"] or consumption["guidance_digests"] != [item["digest"] for item in response["guidance"]]:
            raise DecisionError("decision consumption mismatch")
    elif consumption["decision_digest"] is not None or consumption["selected_alternative_id"] is not None or consumption["guidance_digests"]:
        raise DecisionError("blocked record consumed a decision")
    if safe(record):
        raise DecisionError("privacy-bearing record")
    return {"task_revision": expected_revision, "batch_id": escalation["batch_id"], "decision_status": response["decision_status"], "consumption": consumption["status"], "live_verification": "unverified"}


def project(record, specification_digest):
    validate(record, record["task"]["revision"])
    if not DIGEST.fullmatch(specification_digest):
        raise DecisionError("invalid specification digest")
    response = record["response"]
    result = {"protocol": "awr-awg-decision-integration@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"], "batch_id": record["escalation"]["batch_id"], "request_id": record["request"]["id"], "decision_status": response["decision_status"], "decision_digest": response["decision_digest"], "guidance": response["guidance"], "selected_alternative_id": response["selected_alternative_id"], "consumption": record["consumption"]["status"], "specification_digest": specification_digest, "network": "not_performed", "live_verification": "unverified"}
    result["projection_digest"] = digest(result)
    return result

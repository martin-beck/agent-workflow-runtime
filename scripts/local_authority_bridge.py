#!/usr/bin/env python3
"""Provider-neutral, deterministic local authority envelope model.

This module validates supplied envelopes only. It has no transport and never
persists, executes, or changes authority state.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROTOCOL = {"id": "awr-local-authority-bridge", "version": "1.0.0"}
AUTHORITIES = {"coordinator", "awq", "awg", "ui"}
AMBIGUOUS = {"unknown", "ambiguous", "indeterminate"}
WORKER_AUTHORED = {"decision", "test", "specification"}
ID = re.compile(r"^[A-Z][A-Z0-9-]{0,63}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AuthorityBridgeError(ValueError):
    """An invalid or unsafe offline authority exchange."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AuthorityBridgeError("malformed " + label)
    return value


def binding(task_id: str, revision: int) -> dict[str, Any]:
    """Create a minimal task/revision binding without consulting Coordinator."""
    if not isinstance(task_id, str) or not ID.fullmatch(task_id):
        raise AuthorityBridgeError("invalid task identity")
    if type(revision) is not int or revision < 1:
        raise AuthorityBridgeError("invalid task revision")
    return {"task_id": task_id, "task_revision": revision}


def request_envelope(
    authority: str,
    operation_id: str,
    expected_revision: int,
    payload_digest: str,
    *,
    task_id: str,
    actor: str = "runtime",
    requested_kind: str = "observation",
) -> dict[str, Any]:
    """Build a request envelope; payload content is represented by its digest."""
    if authority not in AUTHORITIES:
        raise AuthorityBridgeError("missing or unsupported authority")
    if not isinstance(operation_id, str) or not ID.fullmatch(operation_id):
        raise AuthorityBridgeError("invalid operation identity")
    if not DIGEST.fullmatch(str(payload_digest)):
        raise AuthorityBridgeError("invalid payload digest")
    bind = binding(task_id, expected_revision)
    _validate_actor(actor, requested_kind)
    return {
        "protocol": dict(PROTOCOL), "authority": authority,
        "operation_id": operation_id, **bind,
        "payload_digest": payload_digest, "actor": actor,
        "requested_kind": requested_kind,
    }


def response_envelope(request: dict[str, Any], outcome: str, *, authority: str | None = None) -> dict[str, Any]:
    """Construct a response-shaped value for a local test harness."""
    if not isinstance(request, dict):
        raise AuthorityBridgeError("malformed request")
    return {
        "protocol": dict(PROTOCOL), "authority": request.get("authority") if authority is None else authority,
        "operation_id": request.get("operation_id"),
        "task_id": request.get("task_id"), "task_revision": request.get("task_revision"),
        "request_digest": digest(request), "outcome": outcome,
    }


def _validate_actor(actor: Any, requested_kind: Any) -> None:
    if actor not in {"runtime", "autonomous_worker", "human"}:
        raise AuthorityBridgeError("missing or invalid actor")
    if requested_kind not in {"observation", "evidence", "decision", "test", "specification"}:
        raise AuthorityBridgeError("unsupported request kind")
    if actor == "autonomous_worker" and requested_kind in WORKER_AUTHORED:
        raise AuthorityBridgeError("autonomous worker cannot author " + requested_kind)


def validate_exchange(
    request: dict[str, Any], response: dict[str, Any], *,
    expected_revision: int, required_authorities: set[str] | None = None,
) -> dict[str, Any]:
    """Validate a revision-fenced exchange and return a non-authoritative view."""
    req_fields = {"protocol", "authority", "operation_id", "task_id", "task_revision", "payload_digest", "actor", "requested_kind"}
    res_fields = {"protocol", "authority", "operation_id", "task_id", "task_revision", "request_digest", "outcome"}
    _object(request, req_fields, "request envelope")
    _object(response, res_fields, "response envelope")
    if request["protocol"] != PROTOCOL or response["protocol"] != PROTOCOL:
        raise AuthorityBridgeError("unsupported protocol")
    if request["authority"] not in AUTHORITIES or not request["authority"]:
        raise AuthorityBridgeError("missing or unsupported authority")
    needed = AUTHORITIES if required_authorities is None else required_authorities
    if not isinstance(needed, set) or not needed <= AUTHORITIES or request["authority"] not in needed:
        raise AuthorityBridgeError("required authority missing")
    if type(expected_revision) is not int or expected_revision < 1:
        raise AuthorityBridgeError("invalid expected revision")
    if request["task_revision"] != expected_revision or response["task_revision"] != expected_revision:
        raise AuthorityBridgeError("stale task revision")
    bind = binding(request["task_id"], expected_revision)
    if response["task_id"] != bind["task_id"]:
        raise AuthorityBridgeError("crossed task binding")
    if not ID.fullmatch(str(request["operation_id"])) or response["operation_id"] != request["operation_id"]:
        raise AuthorityBridgeError("operation correlation mismatch")
    if not DIGEST.fullmatch(str(request["payload_digest"])):
        raise AuthorityBridgeError("invalid payload digest")
    _validate_actor(request["actor"], request["requested_kind"])
    if response["authority"] != request["authority"]:
        raise AuthorityBridgeError("authority response mismatch")
    if response["request_digest"] != digest(request):
        raise AuthorityBridgeError("request response digest mismatch")
    if not isinstance(response["outcome"], str) or not response["outcome"] or response["outcome"] in AMBIGUOUS:
        raise AuthorityBridgeError("ambiguous authority outcome")
    allowed = {
        "coordinator": {"observed", "approved", "stale", "not_found"},
        "awq": {"accepted", "rejected", "not_applicable"},
        "awg": {"approved", "rejected", "requires_ui", "not_applicable"},
        "ui": {"approved", "rejected", "cancelled", "expired"},
    }
    if response["outcome"] not in allowed[request["authority"]]:
        raise AuthorityBridgeError("unsupported authority outcome")
    return {
        "protocol": "awr-local-authority-bridge@1.0.0",
        "authority": request["authority"], "operation_id": request["operation_id"],
        "task_id": bind["task_id"], "task_revision": expected_revision,
        "outcome": response["outcome"], "authority_state": "observed_only",
        "network": "disabled", "durable_state": "not_performed",
    }


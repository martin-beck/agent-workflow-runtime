#!/usr/bin/env python3
"""Deterministic offline model of the AR-0046 Coordinator transport boundary."""
import hashlib
import json
import re
from copy import deepcopy

PROTOCOL = {"id": "awr-coordinator-transport", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
AUTH = re.compile(r"^AUTH-[A-Z0-9-]{1,63}$")
IDS = {k: re.compile(v) for k, v in {
    "task_id": r"^AR-[0-9]{4}$", "session_id": r"^SES-[A-Z0-9-]{1,63}$",
    "owner_id": r"^WRK-[A-Z0-9-]{1,63}$", "lease_id": r"^LSE-[A-Z0-9-]{1,63}$",
    "operation_id": r"^OP-[A-Z0-9-]{1,63}$"
}.items()}
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class TransportError(ValueError):
    pass


class RemoteFailure(TransportError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value) if not isinstance(value, bytes) else value).hexdigest()


def private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(private(v) for v in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


class CoordinatorTransportServer:
    """Authority-shaped server; no socket, filesystem, network, or Coordinator access."""
    def __init__(self, *, revision=5, project_revision="sha256:" + "1" * 64,
                 worktree_digest="sha256:" + "2" * 64, auth_reference="AUTH-AR0046"):
        self.revision = revision
        self.project_revision = project_revision
        self.worktree_digest = worktree_digest
        self.auth_reference = auth_reference
        self.events = []
        self.operations = {}
        self.failures = []

    def inject(self, *codes):
        self.failures.extend(codes)

    def _binding(self, request):
        expected = {"task_id": "AR-0046", "project_key": "agent-workflow-runtime",
                    "project_revision": self.project_revision, "worktree_key": "agent-workflow-runtime-0046",
                    "worktree_digest": self.worktree_digest, "auth_reference": self.auth_reference}
        for key, value in expected.items():
            if request.get(key) != value: raise RemoteFailure("crossed_binding")
        for key in ("task_id", "session_id", "owner_id", "lease_id", "operation_id"):
            if not isinstance(request.get(key), str) or not IDS[key].fullmatch(request[key]):
                raise RemoteFailure("invalid_binding")
        if not isinstance(request.get("auth_proof_digest"), str) or not DIGEST.fullmatch(request["auth_proof_digest"]):
            raise RemoteFailure("invalid_auth_proof")
        if request.get("timeout_ms", 0) not in range(1, 30001) or request.get("attempt", 0) not in range(1, 4):
            raise RemoteFailure("invalid_bounds")
        if private(request): raise RemoteFailure("privacy_violation")

    def handle(self, request):
        if request.get("protocol") != PROTOCOL: raise RemoteFailure("unsupported_protocol")
        self._binding(request)
        operation = request.get("operation")
        if operation not in {"read_revision", "write_event"}: raise RemoteFailure("unknown_operation")
        body = {k: v for k, v in request.items() if k not in {"attempt", "timeout_ms"}}
        fingerprint = digest(body)
        old = self.operations.get(request["operation_id"])
        if old:
            if old["fingerprint"] != fingerprint: raise RemoteFailure("changed_replay")
            return deepcopy(old["response"])
        if self.failures:
            failure = self.failures.pop(0)
            if failure == "ambiguous_after_commit":
                if operation == "write_event": self._commit(request, fingerprint)
                raise RemoteFailure("ambiguous_outcome")
            raise RemoteFailure(failure)
        if request.get("expected_revision") != self.revision:
            raise RemoteFailure("stale_revision")
        response = self._commit(request, fingerprint) if operation == "write_event" else {
            "disposition": "accepted", "task_revision": self.revision,
            "event_count": len(self.events), "operation_id": request["operation_id"]}
        self.operations[request["operation_id"]] = {"fingerprint": fingerprint, "response": response}
        return deepcopy(response)

    def _commit(self, request, fingerprint):
        if request["operation"] == "read_revision":
            return {"disposition": "accepted", "task_revision": self.revision,
                    "event_count": len(self.events), "operation_id": request["operation_id"]}
        event_digest = request.get("event_digest")
        if not isinstance(event_digest, str) or not DIGEST.fullmatch(event_digest):
            raise RemoteFailure("invalid_event_digest")
        event = {"operation_id": request["operation_id"], "event_digest": event_digest,
                 "task_revision": self.revision, "kind": request.get("event_kind")}
        self.events.append(event); self.revision += 1
        response = {"disposition": "accepted", "task_revision": self.revision,
                    "event_count": len(self.events), "event_digest": event_digest,
                    "operation_id": request["operation_id"]}
        self.operations[request["operation_id"]] = {"fingerprint": fingerprint, "response": response}
        return response


class CoordinatorTransportClient:
    def __init__(self, server, binding, *, max_attempts=3):
        self.server = server
        self.binding = deepcopy(binding)
        self.max_attempts = max_attempts
        if max_attempts not in range(1, 4): raise TransportError("invalid retry bound")

    def call(self, operation, operation_id, expected_revision, *, event_kind=None, event_digest=None, timeout_ms=1000):
        request = {"protocol": PROTOCOL, **self.binding, "operation": operation,
                   "operation_id": operation_id, "expected_revision": expected_revision,
                   "timeout_ms": timeout_ms, "attempt": 1}
        if event_kind is not None: request["event_kind"] = event_kind
        if event_digest is not None: request["event_digest"] = event_digest
        request["auth_proof_digest"] = digest({"auth_reference": self.binding.get("auth_reference"), "operation_id": operation_id})
        retryable = {"unavailable", "deadline_exceeded"}
        for attempt in range(1, self.max_attempts + 1):
            request["attempt"] = attempt
            try: return self.server.handle(request)
            except RemoteFailure as exc:
                if exc.code in retryable and attempt < self.max_attempts: continue
                if exc.code == "ambiguous_outcome":
                    return {"disposition": "unknown_outcome", "operation_id": operation_id}
                raise

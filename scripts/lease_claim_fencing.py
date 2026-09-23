"""Deterministic offline AR-0047 lease/claim fencing state machine."""
import hashlib
import json
from copy import deepcopy


class LeaseError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class LeaseStateMachine:
    def __init__(self, revision=5, *, task_id="AR-0047"):
        self.task_id = task_id
        self.revision = revision
        self.status = "open"
        self.owner = self.lease = None
        self.fence = 0
        self.expires = 0
        self.last_time = 0
        self.operations = {}
        self.journal = []

    def _result(self, operation_id, disposition="accepted"):
        return {"disposition": disposition, "operation_id": operation_id,
                "task_revision": self.revision, "owner": self.owner,
                "lease": self.lease, "fence": self.fence,
                "lease_expires": self.expires, "status": self.status}

    def _check_common(self, request):
        if request.get("task_id") != self.task_id:
            raise LeaseError("wrong task")
        if request.get("expected_revision") != self.revision:
            raise LeaseError("stale CAS revision")
        if not isinstance(request.get("now"), int) or isinstance(request["now"], bool) or request["now"] < self.last_time:
            raise LeaseError("non-monotonic observation time")

    def apply(self, request):
        allowed = {"operation", "operation_id", "task_id", "expected_revision", "now", "owner", "lease", "fence", "new_owner", "new_lease", "new_expires", "lease_expires"}
        if set(request) - allowed:
            raise LeaseError("unknown fields")
        operation_id = request.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id.startswith("OP-"):
            raise LeaseError("invalid operation")
        fingerprint = digest(request)
        prior = self.operations.get(operation_id)
        if prior:
            if prior["fingerprint"] != fingerprint:
                raise LeaseError("changed replay")
            return deepcopy(prior["response"])
        self._check_common(request)
        operation = request.get("operation")
        now = request["now"]
        if operation == "claim":
            if self.status != "open" or self.owner is not None:
                raise LeaseError("task already owned")
            self.owner, self.lease = request.get("owner"), request.get("lease")
            self.fence += 1
            self.expires = request.get("new_expires", 0)
            if not self.owner or not self.lease or self.expires <= now:
                raise LeaseError("invalid claim lease")
            self.status = "in_progress"
            self.revision += 1
        else:
            if request.get("owner") != self.owner or request.get("lease") != self.lease or request.get("fence") != self.fence:
                raise LeaseError("owner, lease, or fence mismatch")
            if operation == "heartbeat":
                if now >= self.expires or now <= self.last_time or request.get("new_expires", 0) <= self.expires:
                    raise LeaseError("invalid heartbeat")
                self.expires = request["new_expires"]
            elif operation in {"handoff", "recover_expired"}:
                if operation == "recover_expired" and now < self.expires:
                    raise LeaseError("lease not expired")
                if operation == "handoff" and now >= self.expires:
                    raise LeaseError("lease expired")
                if not request.get("new_owner") or not request.get("new_lease") or request.get("new_expires", 0) <= now:
                    raise LeaseError("invalid replacement lease")
                self.owner, self.lease = request["new_owner"], request["new_lease"]
                self.expires = request["new_expires"]
                self.fence += 1
                self.revision += 1
            elif operation == "release":
                if now >= self.expires:
                    raise LeaseError("lease expired")
                self.owner = self.lease = None
                self.expires = 0
                self.status = "open"
                self.revision += 1
            else:
                raise LeaseError("unknown operation")
        self.last_time = now
        response = self._result(operation_id)
        self.operations[operation_id] = {"fingerprint": fingerprint, "response": deepcopy(response)}
        entry = {"operation_id": operation_id, "operation": operation, "revision": self.revision, "fence": self.fence}
        entry["previous_digest"] = self.journal[-1]["digest"] if self.journal else "sha256:" + "0" * 64
        entry["digest"] = digest(entry)
        self.journal.append(entry)
        return response


class AmbiguousCommit:
    """Injects a transport loss after one committed operation, without guessing."""
    def __init__(self, state):
        self.state, self.used = state, False

    def apply(self, request):
        if not self.used:
            self.used = True
            self.state.apply(request)
            raise LeaseError("ambiguous outcome")
        return self.state.apply(request)

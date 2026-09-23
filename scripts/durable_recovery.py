#!/usr/bin/env python3
"""Deterministic offline model for AR-0036 durable journal recovery."""
import copy
import hashlib
import json
import re

GENESIS = "sha256:" + "0" * 64
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = {"session": re.compile(r"^SES-[A-Z0-9-]{1,63}$"), "worker": re.compile(r"^WRK-[A-Z0-9-]{1,63}$"), "lease": re.compile(r"^LSE-[A-Z0-9-]{1,63}$"), "operation": re.compile(r"^OP-[A-Z0-9-]{1,63}$"), "checkpoint": re.compile(r"^CHK-[A-Z0-9-]{1,63}$")}
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|command|executable", re.I)


class RecoveryError(ValueError):
    """A fail-closed durability or binding violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return all(not PRIVATE.search(str(k)) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and PRIVATE.search(value))


class DurableSession:
    """A memory-only append/replay/crash harness; it performs no file I/O."""

    def __init__(self, *, task_revision, session_id, worker_id, lease_id, fence=1):
        if task_revision != 3 or not all(pattern.fullmatch(value) for pattern, value in ((ID["session"], session_id), (ID["worker"], worker_id), (ID["lease"], lease_id))):
            raise RecoveryError("invalid revision or binding")
        self.binding = {"task": {"id": "AR-0036", "revision": 3}, "project": "agent-workflow-runtime", "worktree": "agent-workflow-runtime-0036", "session_id": session_id}
        self.worker, self.lease, self.fence = worker_id, lease_id, fence
        self.records, self.operations, self.checkpoints = [], {}, {}
        self.pending, self.state = None, "active"

    def _guard(self, worker, lease, fence):
        if self.state in {"ambiguous", "blocked", "completed"} or (worker, lease, fence) != (self.worker, self.lease, self.fence):
            raise RecoveryError("stale or fenced actor")

    def append(self, *, operation_id, event, payload, worker=None, lease=None, fence=None, crash=False):
        worker, lease, fence = worker or self.worker, lease or self.lease, self.fence if fence is None else fence
        self._guard(worker, lease, fence)
        if not ID["operation"].fullmatch(operation_id) or event not in {"start", "progress", "interrupt", "complete"} or not isinstance(payload, dict) or not _safe(payload):
            raise RecoveryError("malformed or private append")
        request = {"event": event, "payload": copy.deepcopy(payload), "worker": worker, "lease": lease, "fence": fence}
        if operation_id in self.operations:
            if self.operations[operation_id]["request"] != request:
                raise RecoveryError("changed replay")
            return copy.deepcopy(self.operations[operation_id]["result"])
        body = {**self.binding, "schema_version": 1, "sequence": len(self.records) + 1, "operation_id": operation_id, "event": event, "payload": request["payload"], "worker": worker, "lease": lease, "fence": fence, "previous_digest": self.records[-1]["record_digest"] if self.records else GENESIS}
        result = {**body, "record_digest": sha256(canonical_bytes(body))}
        if crash:
            self.pending = result
            self.state = "ambiguous"
            raise RecoveryError("ambiguous append after write before fsync")
        self.records.append(result)
        response = {"disposition": "committed", "record_digest": result["record_digest"], "sequence": result["sequence"]}
        self.operations[operation_id] = {"request": request, "result": response}
        if event == "interrupt":
            self.state = "interrupted"
        if event == "complete":
            self.state = "completed"
        return copy.deepcopy(response)

    def checkpoint(self, *, checkpoint_id, operation_id, state_digest, input_digest, result_digest):
        self._guard(self.worker, self.lease, self.fence)
        if self.state not in {"active", "interrupted"} or not ID["checkpoint"].fullmatch(checkpoint_id) or operation_id not in self.operations or not all(DIGEST.fullmatch(v) for v in (state_digest, input_digest, result_digest)):
            raise RecoveryError("invalid checkpoint")
        checkpoint = {"checkpoint_id": checkpoint_id, "operation_id": operation_id, "sequence": len(self.records), "head_digest": self.records[-1]["record_digest"], "state_digest": state_digest, "input_digest": input_digest, "result_digest": result_digest, "worker": self.worker, "lease": self.lease, "fence": self.fence}
        checkpoint["checkpoint_digest"] = sha256(canonical_bytes(checkpoint))
        self.checkpoints[checkpoint_id] = checkpoint
        self.state = "recoverable" if self.state == "interrupted" else self.state
        return copy.deepcopy(checkpoint)

    def crash_recover(self, *, checkpoint_id, worker, lease, fence):
        if self.state != "ambiguous" or checkpoint_id not in self.checkpoints or (worker, lease, fence) == (self.worker, self.lease, self.fence) or fence <= self.fence:
            raise RecoveryError("recovery requires an unambiguous checkpoint and newer fence")
        checkpoint = self.checkpoints[checkpoint_id]
        if checkpoint["head_digest"] != (self.records[-1]["record_digest"] if self.records else GENESIS):
            raise RecoveryError("checkpoint head mismatch")
        self.worker, self.lease, self.fence = worker, lease, fence
        self.pending = None
        self.state = "recoverable"
        return {"disposition": "recovered", "checkpoint_id": checkpoint_id, "worker": worker, "lease": lease, "fence": fence, "head_digest": checkpoint["head_digest"]}

    def replay_checkpoint(self, checkpoint_id):
        if self.state != "recoverable" or checkpoint_id not in self.checkpoints:
            raise RecoveryError("checkpoint is not replayable")
        checkpoint = self.checkpoints[checkpoint_id]
        if checkpoint["head_digest"] != (self.records[-1]["record_digest"] if self.records else GENESIS):
            raise RecoveryError("replay digest mismatch")
        self.state = "active"
        return {"disposition": "replayed", "checkpoint_id": checkpoint_id, "head_digest": checkpoint["head_digest"], "fence": self.fence}


def validate_records(records):
    if not isinstance(records, list):
        raise RecoveryError("records must be a list")
    previous = GENESIS
    for number, record in enumerate(records, 1):
        if not isinstance(record, dict) or record.get("sequence") != number or record.get("previous_digest") != previous:
            raise RecoveryError("broken journal chain")
        body = dict(record)
        digest = body.pop("record_digest", None)
        if not DIGEST.fullmatch(str(digest)) or sha256(canonical_bytes(body)) != digest:
            raise RecoveryError("record digest mismatch")
        previous = digest
    return previous

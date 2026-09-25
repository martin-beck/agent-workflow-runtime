# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Durable, lease-fenced operator projection for autonomous local runs.

This module records operator intent and verified runtime observations. It never
starts a provider or treats a command request as proof that it took effect.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

GENESIS = "sha256:" + "0" * 64
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Z][A-Z0-9-]{0,63}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|command|executable", re.I)
STATES = {"starting", "running", "interrupt_requested", "interrupted", "resume_requested", "cancel_requested", "cancelled", "blocked", "awaiting_decision", "failed", "accepted", "unknown"}


class RunOperationsError(ValueError):
    """Malformed, stale, crossed, or unverifiable run operation."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: Any) -> str:
    return sha256(value if isinstance(value, bytes) else canonical(value))


def _safe(value: Any) -> bool:
    if isinstance(value, dict):
        return all(not PRIVATE.search(str(k)) and _safe(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def _binding(value: Any) -> dict[str, Any]:
    fields = {"run_id", "task_id", "task_revision", "project", "worktree_key", "worktree_digest", "graph_digest", "owner", "session_id", "lease_id", "lease_fence", "lease_expires_at", "event_budget", "accounting_budget"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RunOperationsError("binding_shape_invalid")
    if not IDENT.fullmatch(str(value["run_id"])) or not TASK.fullmatch(str(value["task_id"])):
        raise RunOperationsError("run_identity_invalid")
    if type(value["task_revision"]) is not int or value["task_revision"] < 1:
        raise RunOperationsError("task_revision_invalid")
    for key in ("project", "worktree_key"):
        if not isinstance(value[key], str) or not LABEL.fullmatch(value[key]):
            raise RunOperationsError("binding_identifier_invalid")
    for key in ("owner", "session_id", "lease_id"):
        if not isinstance(value[key], str) or not IDENT.fullmatch(value[key]): raise RunOperationsError("binding_identifier_invalid")
    for key in ("worktree_digest", "graph_digest"):
        if not isinstance(value[key], str) or not DIGEST.fullmatch(value[key]):
            raise RunOperationsError("binding_digest_invalid")
    if type(value["lease_fence"]) is not int or value["lease_fence"] < 1 or type(value["lease_expires_at"]) not in (int, float):
        raise RunOperationsError("lease_invalid")
    if type(value["event_budget"]) is not int or not 1 <= value["event_budget"] <= 10000 or type(value["accounting_budget"]) is not int or not 0 <= value["accounting_budget"] <= 10**12:
        raise RunOperationsError("budget_invalid")
    if not _safe(value):
        raise RunOperationsError("private_binding_rejected")
    return dict(value)


class RunOperations:
    """Atomic hash-linked journal with revision and lease checks on writes."""

    def __init__(self, path: Path, *, clock=time.time):
        self.path = Path(path).absolute()
        self.clock = clock
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        if self.path.is_symlink() or self.lock_path.is_symlink():
            raise RunOperationsError("journal_symlink_rejected")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _locked(self):
        class Lock:
            def __init__(lock, owner): lock.owner = owner
            def __enter__(lock):
                lock.handle = lock.owner.lock_path.open("a+"); fcntl.flock(lock.handle.fileno(), fcntl.LOCK_EX); return lock
            def __exit__(lock, *_):
                fcntl.flock(lock.handle.fileno(), fcntl.LOCK_UN); lock.handle.close()
        return Lock(self)

    def _save(self, value: dict[str, Any]) -> None:
        fd, name = tempfile.mkstemp(prefix=".run-ops-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(value) + b"\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
            directory = os.open(self.path.parent, os.O_DIRECTORY); os.fsync(directory); os.close(directory)
        finally:
            if os.path.exists(name): os.unlink(name)

    def _load(self) -> dict[str, Any]:
        try: value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc: raise RunOperationsError("journal_unavailable") from exc
        if not isinstance(value, dict) or set(value) != {"schema_version", "binding", "state", "revision", "checkpoint_digest", "events", "accounting", "artifacts"} or value["schema_version"] != 1:
            raise RunOperationsError("journal_shape_invalid")
        _binding(value["binding"])
        if value["state"] not in STATES or type(value["revision"]) is not int or value["revision"] < 1:
            raise RunOperationsError("journal_state_invalid")
        if not isinstance(value["events"], list) or value["revision"] != len(value["events"]) or len(value["events"]) > value["binding"]["event_budget"]:
            raise RunOperationsError("journal_projection_invalid")
        previous = GENESIS
        for sequence, event in enumerate(value["events"], 1):
            if not isinstance(event, dict): raise RunOperationsError("journal_integrity_failure")
            body = {k: v for k, v in event.items() if k != "event_digest"}
            expected_fields = {"sequence", "operation_id", "action", "state_before", "state_after", "task_revision", "worker_id", "session_id", "lease_id", "lease_fence", "coordinator_state", "runtime_state", "authority_observations", "failure_code", "checkpoint_digest", "observation_digest", "accounting", "artifacts", "previous_digest", "event_digest"}
            if event.get("action") == "recover": expected_fields.add("recovery_binding")
            if (set(event) != expected_fields
                    or event["sequence"] != sequence or event["previous_digest"] != previous
                    or event["task_revision"] != value["binding"]["task_revision"]
                    or not DIGEST.fullmatch(str(event["event_digest"])) or event["event_digest"] != digest(body)
                    or not _safe(event)):
                raise RunOperationsError("journal_integrity_failure")
            previous = event["event_digest"]
        if not isinstance(value["accounting"], dict) or not isinstance(value["artifacts"], list):
            raise RunOperationsError("journal_projection_invalid")
        if any(not isinstance(event.get("accounting"), dict) or set(event["accounting"]) != {"consumed_delta"}
               or type(event["accounting"]["consumed_delta"]) is not int or event["accounting"]["consumed_delta"] < 0
               or not isinstance(event.get("artifacts"), list) for event in value["events"]):
            raise RunOperationsError("journal_projection_invalid")
        deltas = [event["accounting"]["consumed_delta"] for event in value["events"]]
        budget = value["accounting"].get("budget")
        consumed = sum(deltas) if all(type(delta) is int and delta >= 0 for delta in deltas) else -1
        if (type(budget) is not int or budget != value["binding"]["accounting_budget"]
                or value["accounting"] != {"budget": budget, "consumed": consumed, "remaining": budget - consumed}
                or consumed < 0 or consumed > budget
                or any(not isinstance(item, dict) or set(item) != {"artifact_id", "digest"} or not IDENT.fullmatch(str(item["artifact_id"])) or not DIGEST.fullmatch(str(item["digest"])) for item in value["artifacts"])
                or len({item["artifact_id"] for item in value["artifacts"]}) != len(value["artifacts"])):
            raise RunOperationsError("journal_projection_invalid")
        if value["checkpoint_digest"] is not None and not DIGEST.fullmatch(str(value["checkpoint_digest"])):
            raise RunOperationsError("journal_projection_invalid")
        if value["events"] and value["events"][-1]["state_after"] != value["state"]:
            raise RunOperationsError("journal_projection_invalid")
        return value

    def start(self, binding: dict[str, Any], operation_id: str) -> dict[str, Any]:
        bound = _binding(binding)
        if not IDENT.fullmatch(operation_id): raise RunOperationsError("operation_id_invalid")
        with self._locked():
            if self.path.exists(): raise RunOperationsError("run_already_exists")
            value = {"schema_version": 1, "binding": bound, "state": "starting", "revision": 1, "checkpoint_digest": None, "events": [],
                     "accounting": {"budget": bound["accounting_budget"], "consumed": 0, "remaining": bound["accounting_budget"]}, "artifacts": []}
            self._append(value, operation_id, "start", "starting", "starting", None, 0, [])
            self._save(value)
            return self._board(value)

    def apply(self, command: str, *, run_id: str, operation_id: str, expected_revision: int, lease_id: str, lease_fence: int,
              observation: dict[str, Any] | None = None, accounting_delta: int = 0, artifacts: list[dict[str, str]] | None = None) -> dict[str, Any]:
        if not IDENT.fullmatch(operation_id): raise RunOperationsError("operation_id_invalid")
        if command not in {"observe", "interrupt", "resume", "cancel", "recover"}: raise RunOperationsError("command_invalid")
        observation = observation or {}; artifacts = artifacts or []
        if not isinstance(observation, dict) or not isinstance(artifacts, list) or not _safe(observation): raise RunOperationsError("observation_invalid")
        with self._locked():
            value = self._load(); binding = value["binding"]
            if run_id != binding["run_id"]: raise RunOperationsError("run_binding_mismatch")
            if expected_revision != value["revision"]:
                raise RunOperationsError("stale_revision")
            if (lease_id, lease_fence) != (binding["lease_id"], binding["lease_fence"]): raise RunOperationsError("stale_lease")
            # The lease remains usable through its recorded expiry instant;
            # recovery is safe only once wall time has advanced beyond it.
            if command != "recover" and self.clock() > binding["lease_expires_at"]: raise RunOperationsError("lease_expired")
            if command == "recover" and self.clock() <= binding["lease_expires_at"]: raise RunOperationsError("lease_still_active")
            prior = value["state"]
            state, safe_observation = self._transition(command, prior, observation, value.get("checkpoint_digest"))
            if command == "observe":
                if (observation["worker_id"], observation["session_id"], observation["lease_id"], observation["lease_fence"]) != (binding["owner"], binding["session_id"], binding["lease_id"], binding["lease_fence"]):
                    raise RunOperationsError("observation_binding_mismatch")
            if type(accounting_delta) is not int or accounting_delta < 0 or value["accounting"]["consumed"] + accounting_delta > value["accounting"]["budget"]:
                raise RunOperationsError("accounting_budget_exceeded")
            clean_artifacts = []
            for artifact in artifacts:
                if not isinstance(artifact, dict) or set(artifact) != {"artifact_id", "digest"} or not IDENT.fullmatch(str(artifact["artifact_id"])) or not DIGEST.fullmatch(str(artifact["digest"])):
                    raise RunOperationsError("artifact_reference_invalid")
                if artifact in value["artifacts"] or artifact in clean_artifacts: raise RunOperationsError("artifact_replay")
                clean_artifacts.append(dict(artifact))
            value["accounting"]["consumed"] += accounting_delta
            value["accounting"]["remaining"] -= accounting_delta
            value["artifacts"].extend(clean_artifacts)
            self._append(value, operation_id, command, prior, state, safe_observation, accounting_delta, clean_artifacts)
            if command == "recover":
                if observation["new_lease_fence"] <= binding["lease_fence"] or observation["new_lease_id"] == binding["lease_id"]:
                    raise RunOperationsError("recovery_fence_invalid")
                if observation["new_lease_expires_at"] <= self.clock():
                    raise RunOperationsError("recovery_fence_invalid")
                value["binding"]["lease_id"] = observation["new_lease_id"]
                value["binding"]["lease_fence"] = observation["new_lease_fence"]
                value["binding"]["owner"] = observation["new_worker_id"]
                value["binding"]["lease_expires_at"] = observation["new_lease_expires_at"]
            if command == "observe" and state == "interrupted": value["checkpoint_digest"] = observation["checkpoint_digest"]
            if command == "observe" and state == "running": value["checkpoint_digest"] = None
            value["state"] = state; value["revision"] += 1
            self._save(value)
            return self._board(value)

    @staticmethod
    def _transition(command: str, prior: str, observation: dict[str, Any], checkpoint_digest: str | None) -> tuple[str, dict[str, Any]]:
        requested = {"interrupt": ("running", "interrupt_requested"), "resume": ("interrupted", "resume_requested"), "cancel": ({"starting", "running", "interrupt_requested", "interrupted", "resume_requested", "unknown"}, "cancel_requested")}
        if command in requested:
            allowed, after = requested[command]
            if prior not in (allowed if isinstance(allowed, set) else {allowed}): raise RunOperationsError("invalid_lifecycle_transition")
            if command == "resume" and (set(observation) != {"checkpoint_digest"} or observation["checkpoint_digest"] != checkpoint_digest or not DIGEST.fullmatch(str(observation["checkpoint_digest"]))):
                raise RunOperationsError("checkpoint_mismatch")
            return after, {"effect": "requested", "confirmed": False}
        if command == "observe":
            fields = {"runtime_state", "coordinator_state", "worker_id", "session_id", "lease_id", "lease_fence", "checkpoint_digest", "authority_observations", "failure_code"}
            if set(observation) != fields or observation["runtime_state"] not in STATES: raise RunOperationsError("observation_shape_invalid")
            state = observation["runtime_state"]
            allowed_states = {
                "starting": {"running", "blocked", "failed", "unknown"},
                "running": {"running", "interrupted", "blocked", "awaiting_decision", "failed", "accepted", "unknown"},
                "interrupt_requested": {"interrupted", "running", "failed", "unknown"},
                "interrupted": {"interrupted", "unknown"},
                "resume_requested": {"running", "interrupted", "failed", "unknown"},
                "cancel_requested": {"cancelled", "running", "failed", "unknown"},
                "unknown": {"unknown", "running", "interrupted", "failed", "blocked"},
                "blocked": {"blocked", "unknown"}, "failed": {"failed", "unknown"},
                "awaiting_decision": {"awaiting_decision", "accepted", "blocked", "failed", "unknown"},
            }
            if state not in allowed_states.get(prior, set()): raise RunOperationsError("unverified_lifecycle_transition")
            # Completion only follows explicit Coordinator terminal and all authority evidence.
            if state == "accepted" and (observation["coordinator_state"] != "done" or observation["authority_observations"] != {"awq": "accepted", "awg": "approved", "ui": "completed"}):
                raise RunOperationsError("success_evidence_incomplete")
            if state == "cancelled" and observation["coordinator_state"] != "cancelled": raise RunOperationsError("cancellation_unconfirmed")
            if observation["coordinator_state"] not in {"running", "done", "cancelled", "failed", "blocked", "unknown"}:
                raise RunOperationsError("authority_observation_invalid")
            if state == "interrupted" and (not isinstance(observation["checkpoint_digest"], str) or not DIGEST.fullmatch(observation["checkpoint_digest"])):
                raise RunOperationsError("checkpoint_required")
            for field in ("worker_id", "session_id", "lease_id"):
                if observation[field] and not IDENT.fullmatch(observation[field]): raise RunOperationsError("observation_binding_mismatch")
            if observation["failure_code"] and not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", observation["failure_code"]): raise RunOperationsError("failure_code_invalid")
            if not isinstance(observation["authority_observations"], dict) or not set(observation["authority_observations"]).issubset({"coordinator", "awq", "awg", "ui"}): raise RunOperationsError("authority_observation_invalid")
            allowed = {"coordinator": {"running", "done", "cancelled", "failed", "blocked", "unknown"},
                       "awq": {"accepted", "rejected", "blocked", "unknown", "not_submitted"},
                       "awg": {"approved", "rejected", "escalated", "unknown", "not_requested"},
                       "ui": {"completed", "rejected", "cancelled", "awaiting", "unknown", "not_requested"}}
            if any(value not in allowed[key] for key, value in observation["authority_observations"].items()):
                raise RunOperationsError("authority_observation_invalid")
            return state, dict(observation)
        if command == "recover":
            required = {"checkpoint_digest", "new_worker_id", "new_lease_id", "new_lease_fence", "new_lease_expires_at", "runtime_state"}
            if prior not in {"unknown", "interrupted", "failed", "blocked"} or set(observation) != required:
                raise RunOperationsError("recovery_checkpoint_required")
            if (observation["checkpoint_digest"] != checkpoint_digest or not DIGEST.fullmatch(str(observation["checkpoint_digest"]))
                    or not IDENT.fullmatch(str(observation["new_lease_id"]))
                    or not IDENT.fullmatch(str(observation["new_worker_id"]))
                    or type(observation["new_lease_fence"]) is not int or observation["new_lease_fence"] <= 0
                    or type(observation["new_lease_expires_at"]) not in (int, float) or observation["new_lease_expires_at"] <= 0
                    or observation["runtime_state"] != "running"):
                raise RunOperationsError("recovery_fence_invalid")
            return "running", dict(observation)
        raise RunOperationsError("command_invalid")

    @staticmethod
    def _append(value: dict[str, Any], op: str, command: str, before: str, after: str, observation: dict[str, Any] | None, accounting_delta: int, artifacts: list[dict[str, str]]) -> None:
        if len(value["events"]) >= value["binding"]["event_budget"]: raise RunOperationsError("event_budget_exceeded")
        if any(event["operation_id"] == op for event in value["events"]): raise RunOperationsError("operation_replay")
        body = {"sequence": len(value["events"]) + 1, "operation_id": op, "action": command,
                "state_before": before, "state_after": after, "task_revision": value["binding"]["task_revision"],
                "worker_id": observation.get("worker_id", value["binding"]["owner"]) if observation else value["binding"]["owner"], "session_id": value["binding"]["session_id"],
                "lease_id": value["binding"]["lease_id"], "lease_fence": value["binding"]["lease_fence"],
                "coordinator_state": observation.get("coordinator_state") if observation else None,
                "runtime_state": observation.get("runtime_state") if observation else None,
                "authority_observations": observation.get("authority_observations", {}) if observation else {},
                "failure_code": observation.get("failure_code", "") if observation else "",
                "checkpoint_digest": observation.get("checkpoint_digest") if observation else None,
                "observation_digest": digest(observation or {}), "accounting": {"consumed_delta": accounting_delta},
                "artifacts": artifacts, "previous_digest": value["events"][-1]["event_digest"] if value["events"] else GENESIS}
        if command == "recover":
            body["recovery_binding"] = {"worker_id": observation["new_worker_id"], "lease_id": observation["new_lease_id"],
                                        "lease_fence": observation["new_lease_fence"], "lease_expires_at": observation["new_lease_expires_at"]}
        value["events"].append({**body, "event_digest": digest(body)})

    @staticmethod
    def _board(value: dict[str, Any]) -> dict[str, Any]:
        binding = value["binding"]
        latest = value["events"][-1]
        return {"run_id": binding["run_id"], "task_id": binding["task_id"], "task_revision": binding["task_revision"],
                "project": binding["project"], "worktree_key": binding["worktree_key"], "session_id": binding["session_id"],
                "owner": binding["owner"], "lease_id": binding["lease_id"], "lease_fence": binding["lease_fence"],
                "lease_expires_at": binding["lease_expires_at"], "coordinator_state": latest["coordinator_state"] or "unknown",
                "authority_observations": dict(latest["authority_observations"]), "failure_code": latest["failure_code"],
                "checkpoint_digest": value["checkpoint_digest"],
                "status": value["state"], "revision": value["revision"], "events": len(value["events"]),
                "accounting": dict(value["accounting"]), "artifacts": list(value["artifacts"]),
                "head_digest": value["events"][-1]["event_digest"] if value["events"] else GENESIS,
                "provider": "not_performed", "credentials": "not_inspected", "remote_verification": "unverified"}

    def status(self, run_id: str) -> dict[str, Any]:
        with self._locked():
            value = self._load()
            if value["binding"]["run_id"] != run_id: raise RunOperationsError("run_not_found")
            return self._board(value)

    def follow(self, run_id: str, after_sequence: int = 0) -> list[dict[str, Any]]:
        with self._locked():
            value = self._load()
            if value["binding"]["run_id"] != run_id: raise RunOperationsError("run_not_found")
            if type(after_sequence) is not int or after_sequence < 0 or after_sequence > len(value["events"]): raise RunOperationsError("sequence_invalid")
            return [dict(event) for event in value["events"][after_sequence:]]

    def diagnose(self, run_id: str) -> dict[str, Any]:
        board = self.status(run_id)
        return {"run_id": run_id, "status": board["status"], "classification": board["status"] if board["status"] in {"blocked", "awaiting_decision", "failed", "unknown"} else "healthy_or_in_progress",
                "head_digest": board["head_digest"], "evidence_count": len(board["artifacts"]), "accounting": board["accounting"], "provider": "not_performed", "remote_verification": "unverified"}

    def export_evidence(self, run_id: str) -> dict[str, Any]:
        with self._locked():
            value = self._load()
            if value["binding"]["run_id"] != run_id: raise RunOperationsError("run_not_found")
            record = {"schema_version": 1, "binding": dict(value["binding"]), "state": value["state"], "revision": value["revision"], "checkpoint_digest": value["checkpoint_digest"],
                      "events": list(value["events"]), "accounting": dict(value["accounting"]), "artifacts": list(value["artifacts"])}
            record["evidence_digest"] = digest(record)
            return record

    @staticmethod
    def validate_export(record: dict[str, Any]) -> None:
        expected = {"schema_version", "binding", "state", "revision", "checkpoint_digest", "events", "accounting", "artifacts", "evidence_digest"}
        if not isinstance(record, dict) or set(record) != expected or record.get("schema_version") != 1 or record.get("state") not in STATES:
            raise RunOperationsError("export_shape_invalid")
        body = {key: item for key, item in record.items() if key != "evidence_digest"}
        if record["evidence_digest"] != digest(body) or not _safe(body): raise RunOperationsError("export_integrity_failure")
        _binding(record["binding"])
        if type(record["revision"]) is not int or record["revision"] < 1 or not isinstance(record["events"], list) or record["revision"] != len(record["events"]) or len(record["events"]) > record["binding"]["event_budget"]:
            raise RunOperationsError("export_shape_invalid")
        previous = GENESIS
        for sequence, event in enumerate(record.get("events", []), 1):
            if not isinstance(event, dict): raise RunOperationsError("export_journal_integrity_failure")
            event_body = {key: item for key, item in event.items() if key != "event_digest"}
            fields = {"sequence", "operation_id", "action", "state_before", "state_after", "task_revision", "worker_id", "session_id", "lease_id", "lease_fence", "coordinator_state", "runtime_state", "authority_observations", "failure_code", "checkpoint_digest", "observation_digest", "accounting", "artifacts", "previous_digest", "event_digest"}
            if event.get("action") == "recover": fields.add("recovery_binding")
            if (set(event) != fields or event.get("sequence") != sequence or event.get("previous_digest") != previous
                    or event.get("event_digest") != digest(event_body) or not _safe(event)):
                raise RunOperationsError("export_journal_integrity_failure")
            previous = event["event_digest"]
        accounting = record.get("accounting", {})
        if not isinstance(accounting, dict) or set(accounting) != {"budget", "consumed", "remaining"} or not isinstance(record["artifacts"], list):
            raise RunOperationsError("accounting_conservation_failure")
        if any(not isinstance(event.get("accounting"), dict) or set(event["accounting"]) != {"consumed_delta"}
               or type(event["accounting"]["consumed_delta"]) is not int or event["accounting"]["consumed_delta"] < 0
               or not isinstance(event.get("artifacts"), list) for event in record["events"]):
            raise RunOperationsError("accounting_conservation_failure")
        deltas = sum(event["accounting"]["consumed_delta"] for event in record["events"])
        artifacts = record["artifacts"]
        if (any(not isinstance(item, dict) or set(item) != {"artifact_id", "digest"}
                or not IDENT.fullmatch(str(item["artifact_id"])) or not DIGEST.fullmatch(str(item["digest"])) for item in artifacts)
                or len({item["artifact_id"] for item in artifacts}) != len(artifacts)
                or [item for event in record["events"] for item in event["artifacts"]] != artifacts):
            raise RunOperationsError("export_artifact_integrity_failure")
        if (type(accounting["budget"]) is not int or accounting != {"budget": accounting["budget"], "consumed": deltas, "remaining": accounting["budget"] - deltas}
                or accounting["budget"] != record["binding"]["accounting_budget"] or deltas > accounting["budget"]
                or record["events"][-1]["state_after"] != record["state"]):
            raise RunOperationsError("accounting_conservation_failure")

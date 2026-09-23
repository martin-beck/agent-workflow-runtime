#!/usr/bin/env python3
"""Offline standard-library model for the AR-0008 privacy-safe journal."""

import copy
import hashlib
import json
import re

GENESIS = "sha256:" + "0" * 64
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE_KEY = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)
ID = {"record_id": re.compile(r"^JR-[A-Z0-9-]{1,63}$"), "task_id": re.compile(r"^AR-[0-9]{4}$"), "session_id": re.compile(r"^SES-[A-Z0-9-]{1,63}$"), "operation_id": re.compile(r"^OP-[A-Z0-9-]{1,63}$")}
EVENTS = {"session_started", "tool_call", "file_change", "test_result", "quality_result", "checkpointed", "completed", "failed", "interrupted"}
DISPOSITIONS = {"started", "accepted", "rejected", "blocked", "passed", "failed", "cancelled", "completed"}
TERMINAL = {"completed", "failed", "interrupted"}


class JournalError(ValueError):
    """A fail-closed journal violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def redact(value):
    """Return a bounded JSON value with private keys removed and values redacted."""
    if isinstance(value, dict):
        return {str(key): redact(child) for key, child in value.items() if not PRIVATE_KEY.search(str(key))}
    if isinstance(value, list):
        return [redact(child) for child in value]
    if isinstance(value, str) and PRIVATE_VALUE.search(value):
        return "[REDACTED]"
    return value


def _bounded_json(value):
    try:
        encoded = canonical_bytes(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise JournalError("payload is not canonical JSON") from exc
    if len(encoded) > 4096:
        raise JournalError("payload exceeds bounded journal size")


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEY.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(location)
    return errors


def public_projection(records, task_revision, specification_digest):
    if not isinstance(records, list) or not records or not DIGEST.fullmatch(specification_digest):
        raise JournalError("invalid projection input")
    result = {"protocol": "awr-public-journal-evidence@1.0.0", "task_revision": task_revision, "specification_digest": specification_digest, "count": len(records), "first_sequence": records[0]["sequence"], "last_sequence": records[-1]["sequence"], "head_digest": records[-1]["record_digest"]}
    result["safe_digest"] = sha256(canonical_bytes(result))
    return result


class Journal:
    def __init__(self, task_id, task_revision, session_id, *, max_records=64):
        if not ID["task_id"].fullmatch(task_id) or not isinstance(task_revision, int) or isinstance(task_revision, bool) or task_revision < 1 or not ID["session_id"].fullmatch(session_id):
            raise JournalError("invalid journal binding")
        if not isinstance(max_records, int) or isinstance(max_records, bool) or not 1 <= max_records <= 1024:
            raise JournalError("invalid retention limit")
        self.task = {"id": task_id, "revision": task_revision}
        self.session_id, self.max_records = session_id, max_records
        self.records, self.anchor = [], GENESIS
        self.operations = {}

    def append(self, *, record_id, operation_id, event_type, disposition, payload):
        if not ID["record_id"].fullmatch(record_id) or not ID["operation_id"].fullmatch(operation_id) or event_type not in EVENTS or disposition not in DISPOSITIONS or not isinstance(payload, dict):
            raise JournalError("malformed append input")
        normalized = redact(copy.deepcopy(payload))
        _bounded_json(normalized)
        operation_input = {"event_type": event_type, "disposition": disposition, "payload": normalized}
        if operation_id in self.operations:
            if self.operations[operation_id]["input"] != operation_input:
                raise JournalError("changed replay")
            return copy.deepcopy(self.operations[operation_id]["record"])
        if self.records and self.records[-1]["disposition"] in TERMINAL:
            raise JournalError("append follows terminal record")
        sequence = self.records[-1]["sequence"] + 1 if self.records else 1
        if not self.records and (event_type != "session_started" or disposition != "started"):
            raise JournalError("journal must start with session_started")
        body = {"schema_version": 1, "protocol": {"id": "awr-privacy-safe-event-journal", "version": "1.0.0"}, "record_id": record_id, "sequence": sequence, "task": self.task, "session_id": self.session_id, "operation_id": operation_id, "event_type": event_type, "disposition": disposition, "payload": normalized, "previous_record_digest": self.anchor if not self.records else self.records[-1]["record_digest"]}
        record = {**body, "record_digest": sha256(canonical_bytes(body))}
        self.records.append(record)
        self.operations[operation_id] = {"input": operation_input, "record": record}
        if len(self.records) > self.max_records:
            self.anchor = self.records.pop(0)["record_digest"]
        return copy.deepcopy(record)

    def evidence(self, specification_digest):
        return public_projection(self.records, self.task["revision"], specification_digest)


def validate_journal(records, expected_revision, *, anchor=GENESIS):
    if not isinstance(records, list) or not records or len(records) > 1024 or not isinstance(expected_revision, int) or not DIGEST.fullmatch(anchor):
        raise JournalError("malformed journal")
    previous = anchor
    ids, operations, digests = set(), set(), set()
    for position, record in enumerate(records):
        required = {"schema_version", "protocol", "record_id", "sequence", "task", "session_id", "operation_id", "event_type", "disposition", "payload", "previous_record_digest", "record_digest"}
        if not isinstance(record, dict) or set(record) != required or record["schema_version"] != 1 or record["protocol"] != {"id": "awr-privacy-safe-event-journal", "version": "1.0.0"}:
            raise JournalError("unknown or unsupported record")
        if not isinstance(record.get("sequence"), int) or isinstance(record["sequence"], bool) or record["sequence"] < 1 or record["sequence"] != position + (1 if anchor == GENESIS else records[0]["sequence"]):
            raise JournalError("invalid sequence")
        task = record["task"]
        if not isinstance(task, dict) or task.get("revision") != expected_revision or not ID["task_id"].fullmatch(str(task.get("id", ""))) or not ID["session_id"].fullmatch(str(record["session_id"])) or not ID["operation_id"].fullmatch(str(record["operation_id"])) or record["event_type"] not in EVENTS or record["disposition"] not in DISPOSITIONS or not isinstance(record["payload"], dict):
            raise JournalError("invalid binding or record values")
        if record["previous_record_digest"] != previous or not DIGEST.fullmatch(record["record_digest"]) or record["record_id"] in ids or record["operation_id"] in operations or record["record_digest"] in digests or _safe(record["payload"]):
            raise JournalError("replay, privacy, or chain violation")
        body = dict(record); del body["record_digest"]
        if sha256(canonical_bytes(body)) != record["record_digest"]:
            raise JournalError("record digest mismatch")
        ids.add(record["record_id"]); operations.add(record["operation_id"]); digests.add(record["record_digest"]); previous = record["record_digest"]
    if records[-1]["disposition"] not in DISPOSITIONS:
        raise JournalError("invalid final disposition")
    return {"records": len(records), "first_sequence": records[0]["sequence"], "last_sequence": records[-1]["sequence"], "head_digest": previous, "task_revision": expected_revision}

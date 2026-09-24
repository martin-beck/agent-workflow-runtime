"""Bounded privacy-safe local audit journal for operator diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .cli import CliError, canonical
from .install import _safe_home, default_home

AUDIT = "audit.jsonl"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|api.?key", re.I)
ID = re.compile(r"^(?:AR|JOB|EVT|OP)-[A-Z0-9-]{1,63}$")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class AuditJournal:
    def __init__(self, home: Path | None = None):
        self.home = _safe_home(home if home is not None else default_home(), create=True)
        self.path = self.home / AUDIT
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise CliError("audit_journal_unsafe")

    def _records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise CliError("audit_journal_unreadable") from exc
        if len(lines) > 10000 or self.path.stat().st_size > 4 * 1024 * 1024:
            raise CliError("audit_journal_limit")
        records: list[dict[str, Any]] = []
        previous = "sha256:" + "0" * 64
        for line in lines:
            try: record = json.loads(line)
            except json.JSONDecodeError as exc: raise CliError("audit_journal_corrupt") from exc
            if not isinstance(record, dict) or record.get("previous_digest") != previous or record.get("record_digest") != _digest({k: v for k, v in record.items() if k != "record_digest"}):
                raise CliError("audit_journal_chain_invalid")
            previous = record["record_digest"]; records.append(record)
        return records

    def append(self, *, event_id: str, task_id: str, task_revision: int, category: str, status: str, detail: str = "") -> dict[str, Any]:
        records = self._records()
        if not ID.fullmatch(event_id) or not ID.fullmatch(task_id) or type(task_revision) is not int or task_revision < 1:
            raise CliError("audit_binding_invalid")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", category) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", status):
            raise CliError("audit_value_invalid")
        if len(detail) > 4096 or PRIVATE.search(detail):
            raise CliError("audit_private_or_oversized_detail")
        body = {"schema_version": 1, "event_id": event_id, "task_id": task_id, "task_revision": task_revision, "category": category, "status": status, "detail_digest": _digest(detail), "previous_digest": records[-1]["record_digest"] if records else "sha256:" + "0" * 64}
        record = {**body, "record_digest": _digest(body)}
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush(); os.fsync(stream.fileno())
        return {"status": "recorded", "event_id": event_id, "record_digest": record["record_digest"], "private_payload": "not_stored"}

    def status(self) -> dict[str, Any]:
        records = self._records()
        return {"status": "healthy", "records": len(records), "last_digest": records[-1]["record_digest"] if records else None, "payloads": "digest_only"}

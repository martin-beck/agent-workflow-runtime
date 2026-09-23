#!/usr/bin/env python3
"""Offline cross-adapter conformance and deterministic replay model (AR-0022)."""

import hashlib
import json
import re


TASK = {"id": "AR-0022", "revision": 1}
ADAPTERS = ("codex-style", "opencode-style", "opendesk-style")
EVENT_TYPES = ("session_started", "plan_proposed", "tool_call", "file_change", "test_result", "failed", "interrupted", "completed")
DISPOSITIONS = ("accepted", "started", "completed", "failed", "interrupted")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION = re.compile(r"^SES-[A-Z0-9-]{1,63}$")
WORKTREE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
FORBIDDEN = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data|raw.?output|command|executable", re.I)


class ConformanceError(ValueError):
    """Raised when a conformance record cannot be accepted."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe(value):
    if isinstance(value, dict):
        return not any(FORBIDDEN.search(str(key)) for key in value) and all(_safe(child) for child in value.values())
    if isinstance(value, list):
        return all(_safe(child) for child in value)
    return not (isinstance(value, str) and (len(value) > 256 or re.search(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY", value, re.I)))


def _session(session):
    if (not isinstance(session, dict) or set(session) != {"id", "worktree_key", "worktree_digest"}
            or not SESSION.fullmatch(str(session.get("id", "")))
            or not WORKTREE.fullmatch(str(session.get("worktree_key", "")))
            or not DIGEST.fullmatch(str(session.get("worktree_digest", "")))):
        raise ConformanceError("invalid session/worktree binding")


def _adapter(adapter):
    if (not isinstance(adapter, dict) or set(adapter) != {"id", "version"}
            or adapter["id"] not in ADAPTERS or not VERSION.fullmatch(str(adapter["version"]))):
        raise ConformanceError("unsupported adapter identity")


def capability_report(adapter, capabilities):
    """Return a canonical, digest-bound common capability report."""
    _adapter(adapter)
    if not isinstance(capabilities, list) or not capabilities or len(capabilities) > 16:
        raise ConformanceError("capabilities must be bounded and non-empty")
    if any(not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", item) for item in capabilities) or len(set(capabilities)) != len(capabilities):
        raise ConformanceError("invalid capability name or duplicate capability")
    body = {"adapter": adapter, "capabilities": capabilities, "limits": {"max_events": 64, "max_capabilities": 16}}
    return {**body, "digest": sha256(canonical_bytes(body))}


def normalized_event(record):
    """Validate and return one common normalized event with its canonical digest."""
    required = {"sequence", "event_type", "disposition", "task", "session", "adapter", "evidence_digest", "event_digest"}
    if not isinstance(record, dict) or set(record) != required:
        raise ConformanceError("unknown or missing normalized event field")
    if not isinstance(record["sequence"], int) or record["sequence"] < 1 or record["task"] != TASK:
        raise ConformanceError("invalid sequence or AR-0022 revision binding")
    if record["event_type"] not in EVENT_TYPES or record["disposition"] not in DISPOSITIONS:
        raise ConformanceError("unsupported normalized event or disposition")
    _session(record["session"])
    _adapter(record["adapter"])
    if not DIGEST.fullmatch(str(record["evidence_digest"])) or not DIGEST.fullmatch(str(record["event_digest"])) or not _safe(record):
        raise ConformanceError("invalid digest or privacy-bearing event")
    body = {key: record[key] for key in required if key != "event_digest"}
    if record["event_digest"] != sha256(canonical_bytes(body)):
        raise ConformanceError("event digest mismatch")
    return record


def replay(events):
    if not isinstance(events, list) or not events or len(events) > 64:
        raise ConformanceError("replay must be a bounded non-empty list")
    result = []
    binding = None
    seen = set()
    for index, event in enumerate(events, 1):
        event = normalized_event(event)
        if event["sequence"] != index or event["event_digest"] in seen:
            raise ConformanceError("non-contiguous or replayed normalized event")
        current = (event["task"], event["session"], event["adapter"])
        if binding is None:
            binding = current
        elif current != binding:
            raise ConformanceError("replay crosses task, session, or adapter binding")
        seen.add(event["event_digest"])
        result.append(event)
    if result[-1]["event_type"] not in {"completed", "failed", "interrupted"}:
        raise ConformanceError("replay must end terminal")
    return result


def capability_mismatch(reports, required):
    """Report missing capabilities without changing state or executing anything."""
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        raise ConformanceError("required capabilities must be a list of names")
    available = {report["adapter"]["id"]: set(report["capabilities"]) for report in reports}
    missing = {name: [adapter for adapter in ADAPTERS if name not in available.get(adapter, set())] for name in required}
    missing = {name: adapters for name, adapters in missing.items() if adapters}
    return {"disposition": "capability_mismatch" if missing else "capability_compatible", "execute": False, "missing": missing}


def validate_record(record):
    if not isinstance(record, dict) or set(record) != {"task", "capabilities", "replays", "required_capabilities", "mismatch_report"} or record["task"] != TASK:
        raise ConformanceError("invalid AR-0022 envelope")
    reports = []
    for adapter in ADAPTERS:
        report = record["capabilities"].get(adapter)
        if not isinstance(report, dict) or set(report) != {"adapter", "capabilities", "limits", "digest"}:
            raise ConformanceError("missing capability report")
        expected = capability_report(report["adapter"], report["capabilities"])
        if report != expected or report["adapter"]["id"] != adapter:
            raise ConformanceError("capability report digest or identity mismatch")
        reports.append(report)
        replay(record["replays"].get(adapter))
    expected_mismatch = capability_mismatch(reports, record["required_capabilities"])
    if record["mismatch_report"] != expected_mismatch:
        raise ConformanceError("capability mismatch report is not deterministic")
    return {"contract": "awr-adapter-conformance@1.0.0", "adapters": list(ADAPTERS), "replays": {adapter: len(record["replays"][adapter]) for adapter in ADAPTERS}, "mismatch": expected_mismatch["disposition"]}

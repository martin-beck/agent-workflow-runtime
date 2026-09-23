#!/usr/bin/env python3
"""Deterministic, non-executing ASB pilot harness."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-asb-offline-pilot", "version": "1.0.0"}
TASK = {"id": "AR-0044", "revision": 3}
WORKFLOW = ("admission", "supervisor", "adapter", "journal", "awq", "awg", "ui", "publication", "security")
ASB_STAGES = ("setup", "selection", "configuration", "run", "record", "replay", "comparison")
WORKFLOW_STATUS = {"admission": "observed", "supervisor": "observed", "adapter": "observed", "journal": "observed", "awq": "accepted", "awg": "approved", "ui": "completed", "publication": "not_performed", "security": "passed"}
ASB_STATUS = {"setup": "observed", "selection": "observed", "configuration": "observed", "run": "not_performed", "record": "observed", "replay": "observed", "comparison": "observed"}
ASB_DEPENDS = {"setup": [], "selection": ["setup"], "configuration": ["setup", "selection"], "run": ["setup", "selection", "configuration"], "record": ["setup", "selection", "configuration", "run"], "replay": ["setup", "selection", "configuration", "run", "record"], "comparison": ["setup", "selection", "configuration", "run", "record", "replay"]}
AUTHORITIES = {"admission": "coordinator", "supervisor": "supervisor", "adapter": "adapter", "journal": "journal", "awq": "awq", "awg": "awg", "ui": "ui", "publication": "publication", "security": "security"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PRIVATE = re.compile(r"credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|network|command|executable", re.I)


class PilotError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def safe(value):
    if isinstance(value, dict):
        return not any(PRIVATE.search(str(key)) for key in value) and all(safe(item) for item in value.values())
    if isinstance(value, list):
        return all(safe(item) for item in value)
    return not (isinstance(value, str) and (len(value) > 256 or PRIVATE.search(value)))


def require_digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise PilotError("invalid " + name)


def _check_entry(entry, required, task, session, worktree, expected_status, expected_depends):
    if not isinstance(entry, dict) or set(entry) != required:
        raise PilotError("malformed observation")
    if entry["task_revision"] != 3 or entry["session_id"] != session or entry["worktree_digest"] != worktree:
        raise PilotError("exact binding mismatch")
    if entry["status"] != expected_status or entry["depends_on"] != expected_depends:
        raise PilotError("observation semantics mismatch")
    require_digest(entry["evidence_digest"], "evidence digest")
    unsigned = dict(entry)
    unsigned.pop("evidence_digest")
    if entry["evidence_digest"] != digest(unsigned) or not safe(entry):
        raise PilotError("tampered or privacy-bearing observation")


def validate_record(record, expected_revision=3, expected_worktree="agent-workflow-runtime-0044"):
    required = {"schema_version", "protocol", "task", "project", "worktree", "session", "workflow", "asb", "terminal", "evidence"}
    if not isinstance(record, dict) or set(record) != required or record["schema_version"] != 1 or record["protocol"] != PROTOCOL or record["task"] != {"id": "AR-0044", "revision": expected_revision} or expected_revision != 3:
        raise PilotError("unsupported or stale pilot envelope")
    if record["project"] != {"key": "agent-workflow-runtime", "revision": "sha256:" + "1" * 64}:
        raise PilotError("invalid project binding")
    if record["worktree"] != {"key": expected_worktree, "digest": "sha256:" + "2" * 64}:
        raise PilotError("invalid worktree binding")
    if set(record["session"]) != {"id"} or not re.fullmatch(r"SES-[A-Z0-9-]{1,63}", record["session"]["id"]):
        raise PilotError("invalid session binding")
    session, worktree = record["session"]["id"], record["worktree"]["digest"]
    if not isinstance(record["workflow"], list) or len(record["workflow"]) != len(WORKFLOW):
        raise PilotError("invalid workflow trace")
    seen = set()
    for index, entry in enumerate(record["workflow"], 1):
        if entry.get("sequence") != index or entry.get("component") != WORKFLOW[index - 1]:
            raise PilotError("workflow ordering violation")
        component = WORKFLOW[index - 1]
        _check_entry(entry, {"authority", "component", "depends_on", "evidence_digest", "operation_id", "sequence", "session_id", "status", "task_revision", "worktree_digest"}, TASK, session, worktree, WORKFLOW_STATUS[component], list(WORKFLOW[: index - 1]))
        if entry["authority"] != AUTHORITIES[component] or entry["operation_id"] in seen:
            raise PilotError("workflow authority or replay violation")
        seen.add(entry["operation_id"])
    if not isinstance(record["asb"], list) or len(record["asb"]) != len(ASB_STAGES):
        raise PilotError("invalid ASB trace")
    seen = set()
    for index, entry in enumerate(record["asb"], 1):
        stage = ASB_STAGES[index - 1]
        if entry.get("sequence") != index or entry.get("stage") != stage:
            raise PilotError("ASB ordering violation")
        _check_entry(entry, {"depends_on", "evidence_digest", "observation_id", "sequence", "session_id", "stage", "status", "task_revision", "worktree_digest"}, TASK, session, worktree, ASB_STATUS[stage], ASB_DEPENDS[stage])
        if entry["observation_id"] in seen:
            raise PilotError("ASB replay violation")
        seen.add(entry["observation_id"])
    terminal = record["terminal"]
    if set(terminal) != {"status", "execute", "asb_run", "remote_verification", "durable_state", "publication"} or terminal != {"status": "qualified", "execute": False, "asb_run": "not_performed", "remote_verification": "unverified", "durable_state": "not_performed", "publication": "not_performed"}:
        raise PilotError("unsafe terminal projection")
    evidence = record["evidence"]
    if set(evidence) != {"task_revision", "trace_digest", "checker"} or evidence["task_revision"] != 3 or evidence["checker"] != "awr-asb-offline-pilot-checker/1.0.0" or evidence["trace_digest"] != digest({key: value for key, value in record.items() if key != "evidence"}):
        raise PilotError("trace digest mismatch")
    return {"protocol": "awr-asb-offline-pilot@1.0.0", "task_revision": 3, "workflow_observations": len(record["workflow"]), "asb_observations": len(record["asb"]), "terminal": "qualified", "execute": False, "asb_run": "not_performed", "remote_verification": "unverified"}

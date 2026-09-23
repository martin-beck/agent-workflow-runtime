#!/usr/bin/env python3
"""Offline AR-0020 AWQ submission and AWG batched-envelope model."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-awq-awg-bridge", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^(?:AR|EVID|BATCH|DISC|DEC|GUID|SES)-[A-Z0-9-]{1,63}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|personal.?data)", re.I)
CATEGORIES = {"test", "formal", "privacy", "provenance", "lifecycle"}


class BridgeError(ValueError):
    """A fail-closed bridge violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise BridgeError("malformed " + name)
    return value


def safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                errors.append(location + "." + str(key))
            safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE.search(value):
        errors.append(location)
    return errors


def validate(record, expected_revision=1, *, expected_task="AR-0020", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0020", expected_session="SES-AR0020-REFERENCE"):
    obj(record, {"schema_version", "protocol", "task", "project", "worktree", "session", "evidence_references", "oracle_batches"}, "bridge record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise BridgeError("unsupported bridge protocol")
    task = obj(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision} or not ID.fullmatch(task["id"]):
        raise BridgeError("stale or invalid task binding")
    project = obj(record["project"], {"key", "revision"}, "project")
    worktree = obj(record["worktree"], {"key", "digest"}, "worktree")
    session = obj(record["session"], {"id"}, "session")
    if project["key"] != expected_project or not HEX.fullmatch(project["revision"]):
        raise BridgeError("invalid project binding")
    if worktree["key"] != expected_worktree or not DIGEST.fullmatch(worktree["digest"]):
        raise BridgeError("invalid worktree binding")
    if session["id"] != expected_session or not ID.fullmatch(session["id"]):
        raise BridgeError("invalid session binding")
    refs = record["evidence_references"]
    if not isinstance(refs, list) or not refs or len(refs) > 64:
        raise BridgeError("invalid evidence reference count")
    ids, digests = set(), set()
    for seq, ref in enumerate(refs, 1):
        obj(ref, {"id", "sequence", "category", "evidence_digest", "submission_status"}, "evidence reference")
        if not isinstance(ref["sequence"], int) or isinstance(ref["sequence"], bool) or ref["sequence"] != seq or not ID.fullmatch(ref["id"]):
            raise BridgeError("invalid evidence reference sequence")
        if not ref["id"].startswith("EVID-") or ref["id"] in ids or ref["category"] not in CATEGORIES or ref["submission_status"] != "offered_for_awq_review" or not DIGEST.fullmatch(ref["evidence_digest"]):
            raise BridgeError("invalid evidence reference")
        if ref["evidence_digest"] in digests:
            raise BridgeError("replayed evidence digest")
        ids.add(ref["id"]); digests.add(ref["evidence_digest"])
    batches = record["oracle_batches"]
    if not isinstance(batches, list) or not batches or len(batches) > 8:
        raise BridgeError("invalid oracle batch count")
    batch_ids = set()
    for seq, batch in enumerate(batches, 1):
        obj(batch, {"id", "sequence", "discussion", "decision", "guidance"}, "oracle batch")
        if not isinstance(batch["sequence"], int) or isinstance(batch["sequence"], bool) or batch["sequence"] != seq or not ID.fullmatch(batch["id"]) or not batch["id"].startswith("BATCH-") or batch["id"] in batch_ids:
            raise BridgeError("invalid oracle batch")
        batch_ids.add(batch["id"])
        discussion = obj(batch["discussion"], {"id", "kind", "authority", "status", "context_digest", "evidence_ids"}, "discussion envelope")
        if discussion["kind"] != "discussion" or discussion["authority"] != "runtime" or discussion["status"] != "requested" or not ID.fullmatch(discussion["id"]) or not discussion["id"].startswith("DISC-") or not DIGEST.fullmatch(discussion["context_digest"]):
            raise BridgeError("invalid discussion envelope")
        if not isinstance(discussion["evidence_ids"], list) or not discussion["evidence_ids"] or any(item not in ids for item in discussion["evidence_ids"]):
            raise BridgeError("invalid discussion evidence references")
        for kind, prefix in (("decision", "DEC-"), ("guidance", "GUID-")):
            envelope = obj(batch[kind], {"id", "kind", "authority", "status", "payload_digest"}, kind + " envelope")
            if envelope["kind"] != kind or envelope["authority"] != "awg" or envelope["status"] != "received" or not ID.fullmatch(envelope["id"]) or not envelope["id"].startswith(prefix) or not DIGEST.fullmatch(envelope["payload_digest"]):
                raise BridgeError("invalid external " + kind + " envelope")
            if envelope["payload_digest"] in digests:
                raise BridgeError("replayed oracle payload digest")
            digests.add(envelope["payload_digest"])
    if safe(record):
        raise BridgeError("private, unknown, or authority-bearing value")
    return {"evidence_references": len(refs), "oracle_batches": len(batches), "task_revision": expected_revision, "session_id": session["id"]}


def project(record, specification_digest):
    if not DIGEST.fullmatch(specification_digest):
        raise BridgeError("invalid specification digest")
    validate(record, record["task"]["revision"], expected_task=record["task"]["id"], expected_session=record["session"]["id"])
    projection = {"protocol": "awr-awq-awg-bridge@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "session": record["session"], "evidence_references": record["evidence_references"], "oracle_batches": record["oracle_batches"], "quality_status": "not_decided", "oracle_status": "not_decided", "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

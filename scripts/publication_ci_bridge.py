#!/usr/bin/env python3
"""Offline model for the AR-0021 provider-neutral publication/CI bridge."""
import hashlib
import json
import re

PROTOCOL = {"id": "awr-publication-ci-bridge", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^(?:AR-[0-9]{4}|RV-[A-Z0-9-]{1,63}|CI-[A-Z0-9-]{1,63}|EV-[A-Z0-9-]{1,63})$")
BRANCH = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)


class BridgeError(ValueError):
    """A fail-closed publication/CI bridge violation."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise BridgeError("malformed " + name)
    return value


def _digest(value, name):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise BridgeError("invalid " + name)


def _safe(value, location="$", errors=None):
    errors = [] if errors is None else errors
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE.search(str(key)):
                errors.append(location + "." + str(key))
            _safe(child, location + "." + str(key), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _safe(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and PRIVATE_VALUE.search(value):
        errors.append(location)
    return errors


def validate(record, expected_revision=1, *, expected_task="AR-0021", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0021"):
    _object(record, {"schema_version", "protocol", "task", "project", "worktree", "branch", "commit", "review", "merge_handoff", "ci", "publication", "evidence"}, "bridge record")
    if record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise BridgeError("unsupported bridge protocol")
    task = _object(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision}:
        raise BridgeError("stale or invalid task binding")
    project = _object(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise BridgeError("invalid project binding")
    _digest(project["revision"], "project revision")
    worktree = _object(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree:
        raise BridgeError("invalid worktree binding")
    _digest(worktree["digest"], "worktree digest")
    branch = _object(record["branch"], {"name", "head"}, "branch")
    if not BRANCH.fullmatch(branch["name"]) or ".." in branch["name"] or not GIT.fullmatch(branch["head"]):
        raise BridgeError("invalid branch observation")
    commit = _object(record["commit"], {"id", "tree", "parents", "exact_head", "signature", "dco"}, "commit")
    if not GIT.fullmatch(commit["id"]) or not GIT.fullmatch(commit["tree"]) or not isinstance(commit["parents"], list) or len(commit["parents"]) > 2 or any(not GIT.fullmatch(parent) for parent in commit["parents"]):
        raise BridgeError("invalid commit observation")
    if commit["exact_head"] is not True or commit["id"] != branch["head"]:
        raise BridgeError("commit is not exact branch head")
    signature = _object(commit["signature"], {"status", "algorithm", "key_digest"}, "signature")
    if signature["status"] != "valid" or signature["algorithm"] not in {"ssh", "gpg"}:
        raise BridgeError("unsigned or invalid commit signature")
    _digest(signature["key_digest"], "signature key digest")
    dco = _object(commit["dco"], {"status", "trailer_digest"}, "DCO")
    if dco["status"] != "signed":
        raise BridgeError("unsigned DCO")
    _digest(dco["trailer_digest"], "DCO trailer digest")
    head = branch["head"]
    review = _object(record["review"], {"id", "status", "target_head", "evidence_digest"}, "review")
    if not ID.fullmatch(review["id"]) or review["status"] != "approved" or review["target_head"] != head:
        raise BridgeError("review is absent or targets the wrong head")
    _digest(review["evidence_digest"], "review evidence digest")
    handoff = _object(record["merge_handoff"], {"status", "target_head", "evidence_digest"}, "merge handoff")
    if handoff["status"] != "ready" or handoff["target_head"] != head:
        raise BridgeError("merge handoff is not ready or claims execution")
    _digest(handoff["evidence_digest"], "merge handoff evidence digest")
    ci = _object(record["ci"], {"id", "status", "verification", "target_head", "review_id", "evidence_digest"}, "CI")
    if not ID.fullmatch(ci["id"]) or ci["status"] != "success" or ci["verification"] != "unverified" or ci["target_head"] != head or ci["review_id"] != review["id"]:
        raise BridgeError("CI is wrong-head, uncorrelated, or falsely verified")
    _digest(ci["evidence_digest"], "CI evidence digest")
    publication = _object(record["publication"], {"status", "target_head", "evidence_digest"}, "publication")
    if publication["status"] != "not_performed" or publication["target_head"] != head:
        raise BridgeError("publication is not a non-executing observation")
    _digest(publication["evidence_digest"], "publication evidence digest")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or len(evidence) != 7:
        raise BridgeError("invalid evidence count")
    kinds = {"branch", "commit", "review", "merge_handoff", "ci", "publication", "correlation"}
    seen_kinds, seen_ids, seen_digests = set(), set(), set()
    components = {key: record[key] for key in {"branch", "commit", "review", "merge_handoff", "ci", "publication"}}
    components["correlation"] = {"review_id": review["id"], "ci_id": ci["id"], "target_head": head}
    for item in evidence:
        item = _object(item, {"id", "kind", "digest"}, "evidence item")
        if not ID.fullmatch(item["id"]) or item["id"] in seen_ids or item["kind"] in seen_kinds or item["kind"] not in kinds:
            raise BridgeError("replayed or invalid evidence")
        _digest(item["digest"], "evidence digest")
        if item["digest"] in seen_digests or item["digest"] != sha256(canonical_bytes(components[item["kind"]])):
            raise BridgeError("replayed or mismatched evidence digest")
        seen_ids.add(item["id"]); seen_kinds.add(item["kind"]); seen_digests.add(item["digest"])
    if seen_kinds != kinds or _safe(record):
        raise BridgeError("privacy-bearing or incomplete bridge record")
    return {"task_revision": expected_revision, "head": head, "ci": "unverified", "merge_handoff": "ready", "publication": "not_performed"}


def project(record, specification_digest):
    _digest(specification_digest, "specification digest")
    validate(record, record["task"]["revision"], expected_task=record["task"]["id"])
    projection = {"protocol": "awr-publication-ci-evidence@1.0.0", "task": record["task"], "project": record["project"], "worktree": record["worktree"], "branch": record["branch"], "commit": record["commit"], "review": record["review"], "merge_handoff": record["merge_handoff"], "ci": record["ci"], "publication": record["publication"], "specification_digest": specification_digest}
    projection["projection_digest"] = sha256(canonical_bytes(projection))
    return projection

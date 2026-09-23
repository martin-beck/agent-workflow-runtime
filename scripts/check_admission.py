#!/usr/bin/env python3
"""Validate the AR-0001 specification and an offline admission envelope."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TASK = re.compile(r"^AR-[0-9]{4}$")
PRIVATE_KEYS = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|personal.?data)", re.I)
PRIVATE_VALUES = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|(?:BEGIN (?:RSA|OPENSSH|PRIVATE) KEY)|\b(?:password|token|credential)\s*[:=]", re.I)


class AdmissionError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def load_json(path):
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"malformed JSON: {exc}") from exc


def _walk_privacy(value, location="$", seen=None):
    if seen is None:
        seen = []
    if isinstance(value, dict):
        for key, child in value.items():
            if PRIVATE_KEYS.search(str(key)):
                seen.append(f"prohibited field at {location}.{key}")
            _walk_privacy(child, f"{location}.{key}", seen)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_privacy(child, f"{location}[{index}]", seen)
    elif isinstance(value, str) and PRIVATE_VALUES.search(value):
        seen.append(f"prohibited value at {location}")
    return seen


def validate_spec(spec):
    if not isinstance(spec, dict) or spec.get("schema_version") != 1:
        raise AdmissionError("malformed specification: schema_version must be 1")
    required = {"schema_version", "specification_id", "version", "charter", "authority_matrix", "admission_rule", "invariants", "failure_semantics", "compatibility", "limitations"}
    missing = required - set(spec)
    if missing:
        raise AdmissionError(f"malformed specification: missing {sorted(missing)}")
    if not isinstance(spec["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", spec["version"]):
        raise AdmissionError("malformed specification: version must be semver")
    matrix = spec["authority_matrix"]
    if not isinstance(matrix, list) or not matrix:
        raise AdmissionError("missing authority matrix")
    owners = {}
    required_authorities = {"coordinator", "quality", "guidance", "ui", "runtime"}
    present_authorities = set()
    for entry in matrix:
        if not isinstance(entry, dict) or not isinstance(entry.get("authority"), str) or not isinstance(entry.get("domains"), list) or not entry["domains"]:
            raise AdmissionError("malformed authority entry")
        present_authorities.add(entry["authority"])
        for domain in entry["domains"]:
            if not isinstance(domain, str) or not domain:
                raise AdmissionError("malformed authority domain")
            if domain in owners and owners[domain] != entry["authority"]:
                raise AdmissionError(f"unsupported authority overlap: {domain}")
            owners[domain] = entry["authority"]
    missing_authorities = required_authorities - present_authorities
    if missing_authorities:
        raise AdmissionError(f"missing authority: {sorted(missing_authorities)}")
    rule = spec["admission_rule"]
    if not isinstance(rule, dict) or rule.get("id") != "specification-before-implementation":
        raise AdmissionError("malformed admission rule")
    if not isinstance(spec["limitations"], list) or not spec["limitations"]:
        raise AdmissionError("missing limitations")
    return True


def validate_admission(admission, spec, expected_revision, seen_evidence=()):
    validate_spec(spec)
    if not isinstance(admission, dict) or admission.get("schema_version") != 1:
        raise AdmissionError("malformed admission envelope")
    required = {"schema_version", "task", "specification", "evidence", "decision"}
    missing = required - set(admission)
    if missing:
        raise AdmissionError(f"malformed admission: missing {sorted(missing)}")
    task = admission["task"]
    if not isinstance(task, dict) or not TASK.fullmatch(str(task.get("id", ""))) or not isinstance(task.get("revision"), int) or task["revision"] < 1:
        raise AdmissionError("malformed task binding")
    if task["revision"] != expected_revision:
        raise AdmissionError("stale task revision")
    reference = admission["specification"]
    if not isinstance(reference, dict) or reference.get("id") != spec["specification_id"] or reference.get("version") != spec["version"] or not DIGEST.fullmatch(str(reference.get("sha256", ""))):
        raise AdmissionError("malformed specification binding")
    actual = "sha256:" + sha256(canonical_bytes(spec))
    if reference["sha256"] != actual:
        raise AdmissionError("stale specification digest")
    if admission["decision"] != "admit":
        raise AdmissionError("admission decision is not admit")
    evidence = admission["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise AdmissionError("missing evidence")
    ids, digests = set(), set()
    prior = set(seen_evidence)
    for item in evidence:
        if not isinstance(item, dict) or not re.fullmatch(r"^EV-[A-Z0-9-]{1,63}$", str(item.get("id", ""))) or not DIGEST.fullmatch(str(item.get("digest", ""))):
            raise AdmissionError("malformed evidence")
        if item["id"] in ids or item["digest"] in digests or item["id"] in prior or item["digest"] in prior:
            raise AdmissionError("replayed or duplicate evidence")
        ids.add(item["id"])
        digests.add(item["digest"])
    privacy_errors = _walk_privacy(admission)
    if privacy_errors:
        raise AdmissionError("prohibited private data")
    return {"decision": "admit", "task_revision": expected_revision, "specification_digest": actual, "evidence_count": len(evidence)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--admission", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = validate_admission(load_json(args.admission), load_json(args.spec), args.expected_revision)
    except AdmissionError as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

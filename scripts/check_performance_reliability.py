#!/usr/bin/env python3
"""Fail-closed offline checker for AR-0026."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from scripts.performance_reliability import CATEGORIES, PROTOCOL, QualificationError, evaluate_observation, digest
except ModuleNotFoundError:
    from performance_reliability import CATEGORIES, PROTOCOL, QualificationError, evaluate_observation, digest

PRIVATE = re.compile(r"(?:credential|password|secret|token|prompt|transcript|private.?path|host.?identifier|raw.?output|email|personal.?data)", re.I)
PRIVATE_VALUE = re.compile(r"(?:^|[/\\])(?:home|Users|private|secret|credentials)(?:[/\\]|$)|BEGIN (?:RSA|OPENSSH|PRIVATE) KEY|\b(?:password|token|credential)\s*[:=]", re.I)
CHECKER = "awr-performance-reliability-checker/1.0.0"
TOP = {"schema_version", "protocol", "task", "project", "worktree", "qualification", "observations", "result", "evidence"}


class QualificationCheckError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationCheckError("malformed JSON") from exc


def obj(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise QualificationCheckError("malformed " + name)
    return value


def private(value):
    if isinstance(value, dict):
        return any(PRIVATE.search(str(k)) or private(v) for k, v in value.items())
    if isinstance(value, list):
        return any(private(v) for v in value)
    return isinstance(value, str) and bool(PRIVATE_VALUE.search(value))


def validate_spec(spec):
    required = {"schema_version", "specification_id", "version", "title", "normative", "authority", "binding", "categories", "rules", "privacy", "failure_semantics", "limitations", "follow_up"}
    if not isinstance(spec, dict) or set(spec) != required or spec.get("schema_version") != 1 or spec.get("specification_id") != "awr-performance-reliability-qualification" or spec.get("version") != "1.0.0" or spec.get("normative") is not True:
        raise QualificationCheckError("unsupported or malformed specification")
    if set(spec["categories"]) != CATEGORIES or not spec["rules"] or not spec["limitations"]:
        raise QualificationCheckError("incomplete specification")


def validate_record(record, spec, expected_revision=1, expected_task="AR-0026", expected_project="agent-workflow-runtime", expected_worktree="agent-workflow-runtime-0026"):
    validate_spec(spec)
    if not isinstance(record, dict) or set(record) != TOP or record["schema_version"] != 1 or record["protocol"] != PROTOCOL:
        raise QualificationCheckError("malformed protocol envelope")
    task = obj(record["task"], {"id", "revision"}, "task")
    if task != {"id": expected_task, "revision": expected_revision}:
        raise QualificationCheckError("stale task revision")
    project = obj(record["project"], {"key", "revision"}, "project")
    if project["key"] != expected_project:
        raise QualificationCheckError("wrong project binding")
    digest(project["revision"])
    worktree = obj(record["worktree"], {"key", "digest"}, "worktree")
    if worktree["key"] != expected_worktree:
        raise QualificationCheckError("wrong worktree binding")
    digest(worktree["digest"])
    qualification = obj(record["qualification"], {"status", "source", "live_measurement", "max_observations", "max_value"}, "qualification")
    if qualification != {"status": "qualified", "source": "supplied_qualification", "live_measurement": "not_performed", "max_observations": 5, "max_value": 1000000}:
        raise QualificationCheckError("qualification is live, unbounded, or not positive")
    observations = record["observations"]
    if not isinstance(observations, list) or len(observations) != qualification["max_observations"]:
        raise QualificationCheckError("invalid observation count")
    ids, categories, evidence_digests = set(), set(), set()
    results = []
    for observation in observations:
        try:
            result = evaluate_observation(observation)
        except QualificationError as exc:
            raise QualificationCheckError(str(exc)) from exc
        if observation["id"] in ids or observation["category"] in categories or observation["evidence_digest"] in evidence_digests:
            raise QualificationCheckError("replayed observation or evidence")
        if observation["value"] > qualification["max_value"] or sha(canonical({k: observation[k] for k in observation if k != "evidence_digest"})) != observation["evidence_digest"]:
            raise QualificationCheckError("tampered or over-budget observation")
        ids.add(observation["id"]); categories.add(observation["category"]); evidence_digests.add(observation["evidence_digest"]); results.append(result)
    if categories != CATEGORIES or not all(item["passed"] for item in results):
        raise QualificationCheckError("qualification failed")
    expected_result = {"status": "qualified", "source": "supplied_qualification", "live_measurement": "not_performed", "categories": sorted(CATEGORIES)}
    if record["result"] != expected_result or private(record):
        raise QualificationCheckError("result mismatch or privacy violation")
    evidence = obj(record["evidence"], {"task_revision", "specification_digest", "record_digest", "checker"}, "evidence")
    if evidence["task_revision"] != expected_revision or evidence["specification_digest"] != sha(canonical(spec)) or evidence["record_digest"] != sha(canonical({k: record[k] for k in record if k != "evidence"})) or evidence["checker"] != CHECKER:
        raise QualificationCheckError("invalid evidence binding")
    return {"protocol": "awr-performance-reliability-qualification@1.0.0", "task_revision": expected_revision, "status": "qualified", "source": "supplied_qualification", "live_measurement": "not_performed"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(validate_record(load(args.record), load(args.spec), args.expected_revision), sort_keys=True, separators=(",", ":")))
    except (QualificationCheckError, KeyError, TypeError) as exc:
        print("REJECT: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

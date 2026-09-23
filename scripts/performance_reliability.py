#!/usr/bin/env python3
"""Offline model for AR-0026 supplied performance/reliability qualification."""

import math
import re

PROTOCOL = {"id": "awr-performance-reliability-qualification", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CATEGORIES = {"latency", "throughput", "recovery", "resource_use", "failure_behavior"}


class QualificationError(ValueError):
    """A fail-closed qualification violation."""


def digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise QualificationError("invalid digest")


def compare(value, operator, limit):
    if operator == "less_or_equal":
        return value <= limit
    if operator == "greater_or_equal":
        return value >= limit
    raise QualificationError("invalid comparison operator")


def evaluate_observation(observation):
    fields = {"id", "category", "metric", "value", "unit", "specification", "budget", "source", "measurement", "evidence_digest"}
    if not isinstance(observation, dict) or set(observation) != fields:
        raise QualificationError("malformed observation")
    if not isinstance(observation["id"], str) or not re.fullmatch(r"OBS-[A-Z0-9-]{1,31}", observation["id"]):
        raise QualificationError("invalid observation id")
    if observation["category"] not in CATEGORIES or not isinstance(observation["metric"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", observation["metric"]):
        raise QualificationError("invalid observation category or metric")
    value = observation["value"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise QualificationError("invalid observation value")
    specification = observation["specification"]
    if not isinstance(specification, dict) or set(specification) != {"operator", "limit"}:
        raise QualificationError("malformed specification")
    limit = specification["limit"]
    if isinstance(limit, bool) or not isinstance(limit, (int, float)) or not math.isfinite(limit) or limit < 0:
        raise QualificationError("invalid specification limit")
    budget = observation["budget"]
    if not isinstance(budget, dict) or set(budget) != {"max_value"}:
        raise QualificationError("malformed observation budget")
    max_value = budget["max_value"]
    if isinstance(max_value, bool) or not isinstance(max_value, (int, float)) or not math.isfinite(max_value) or max_value < 0 or value > max_value:
        raise QualificationError("observation budget exceeded")
    if observation["source"] != "supplied_qualification" or observation["measurement"] != "not_performed":
        raise QualificationError("live measurement claimed")
    digest(observation["evidence_digest"])
    passed = compare(value, specification["operator"], limit)
    return {"id": observation["id"], "category": observation["category"], "passed": passed, "source": "supplied_qualification", "measurement": "not_performed"}

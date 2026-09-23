#!/usr/bin/env python3
"""Deterministic offline resource-boundary model for AR-0006."""

from dataclasses import dataclass


DIMENSIONS = (
    "cpu_ms", "memory_bytes", "disk_bytes", "network_bytes",
    "process_count", "process_depth",
)
OBSERVATIONS = DIMENSIONS + (
    "elapsed_ms", "process_tree_complete", "cancel_requested",
    "cancel_acknowledged",
)
MAX_VALUE = (1 << 63) - 1


class ResourceBoundaryError(ValueError):
    """A fail-closed budget, observation, or termination violation."""


def _uint(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_VALUE:
        raise ResourceBoundaryError(f"{name} must be a non-negative integer")
    return value


def _bool(value, name):
    if not isinstance(value, bool):
        raise ResourceBoundaryError(f"{name} must be boolean")
    return value


@dataclass(frozen=True)
class ResourceBudget:
    cpu_ms: int
    memory_bytes: int
    disk_bytes: int
    network_bytes: int
    process_count: int
    process_depth: int
    timeout_ms: int

    @classmethod
    def from_mapping(cls, values):
        if not isinstance(values, dict) or set(values) != set(cls.__dataclass_fields__):
            raise ResourceBoundaryError("budget fields must be complete and closed")
        checked = {name: _uint(values[name], name) for name in values}
        if any(value == 0 for value in checked.values()):
            raise ResourceBoundaryError("budgets must be positive")
        return cls(**checked)


@dataclass(frozen=True)
class ResourceObservation:
    cpu_ms: int
    memory_bytes: int
    disk_bytes: int
    network_bytes: int
    process_count: int
    process_depth: int
    elapsed_ms: int
    process_tree_complete: bool
    cancel_requested: bool
    cancel_acknowledged: bool

    @classmethod
    def from_mapping(cls, values):
        if not isinstance(values, dict) or set(values) != set(OBSERVATIONS):
            raise ResourceBoundaryError("observations must be complete and closed")
        checked = {name: _uint(values[name], name) for name in DIMENSIONS + ("elapsed_ms",)}
        checked.update({
            name: _bool(values[name], name)
            for name in ("process_tree_complete", "cancel_requested", "cancel_acknowledged")
        })
        return cls(**checked)


def evaluate(budget, observation):
    """Return a public result; any uncertain input raises and is not accepted."""
    budget = ResourceBudget.from_mapping(budget) if isinstance(budget, dict) else budget
    observation = ResourceObservation.from_mapping(observation) if isinstance(observation, dict) else observation
    if not isinstance(budget, ResourceBudget) or not isinstance(observation, ResourceObservation):
        raise ResourceBoundaryError("invalid boundary inputs")
    exceeded = [name for name in DIMENSIONS if getattr(observation, name) > getattr(budget, name)]
    if observation.elapsed_ms > budget.timeout_ms:
        exceeded.append("timeout_ms")
    if not observation.process_tree_complete:
        exceeded.append("process_tree_complete")
    if observation.cancel_requested and not observation.cancel_acknowledged:
        exceeded.append("cancellation")
    if observation.cancel_acknowledged and not observation.cancel_requested:
        exceeded.append("cancellation_state")
    if exceeded:
        return {"accepted": False, "disposition": "rejected", "violations": exceeded}
    return {"accepted": True, "disposition": "accepted", "violations": []}

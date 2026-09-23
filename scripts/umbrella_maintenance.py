"""Offline reference model for AR-0028 umbrella maintenance."""
import re

PROTOCOL = {"id": "awr-umbrella-maintenance", "version": "1.0.0"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PHASES = ("coordinator", "runtime", "quality", "guidance", "ui", "release", "self_evolution")


class UmbrellaError(ValueError):
    pass


def digest(value, name="digest"):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise UmbrellaError("invalid " + name)


def evaluate(record):
    registration = record["registration"]
    if registration["status"] != "registered" or registration["authority_transfer"] != "none":
        raise UmbrellaError("registration is not authority-preserving")
    if registration["family"] != "agent-workflow" or registration["runtime_key"] != "agent-workflow-runtime":
        raise UmbrellaError("invalid umbrella registration")
    if registration["members"] != ["coordinator", "runtime", "quality", "guidance", "ui"]:
        raise UmbrellaError("incomplete authority membership")
    maintenance = record["maintenance"]
    if maintenance["status"] != "qualified" or maintenance["cycle_id"] != "AR-0028-cycle-1":
        raise UmbrellaError("maintenance cycle is not qualified")
    if maintenance["release"] != "not_performed" or maintenance["remote_verification"] != "unverified":
        raise UmbrellaError("maintenance record exceeds release evidence")
    if maintenance["self_evolution"] != "proposal_only":
        raise UmbrellaError("self-evolution is not proposal-only")
    if not isinstance(record["transitions"], list) or len(record["transitions"]) != len(PHASES):
        raise UmbrellaError("invalid phase count")
    seen = set()
    for index, item in enumerate(record["transitions"]):
        expected = {"id", "phase", "authority", "status", "input_digest", "output_digest"}
        if not isinstance(item, dict) or set(item) != expected:
            raise UmbrellaError("malformed transition")
        if item["id"] in seen or item["phase"] != PHASES[index] or item["status"] != "observed":
            raise UmbrellaError("replayed or out-of-order transition")
        if item["authority"] != item["phase"]:
            raise UmbrellaError("unauthorized transition")
        digest(item["input_digest"], "transition input")
        digest(item["output_digest"], "transition output")
        seen.add(item["id"])
    if set(seen) != {"TR-" + str(index + 1) for index in range(7)}:
        raise UmbrellaError("invalid transition identifiers")
    return {"status": "maintenance_ready", "registration": "registered", "phases": len(PHASES), "release": "not_performed", "remote_verification": "unverified"}

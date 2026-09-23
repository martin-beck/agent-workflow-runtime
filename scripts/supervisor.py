#!/usr/bin/env python3
"""Small offline supervisor lifecycle model for AR-0005."""

from dataclasses import dataclass


class SupervisorError(ValueError):
    """A fail-closed lifecycle or lease violation."""


@dataclass
class SupervisorState:
    task_revision: int
    session_id: str
    worker_id: str
    lease_id: str
    lease_expires: int
    state: str = "admitted"
    last_time: int = 0
    sequence: int = 0

    def action(self, operation, *, worker, lease, now, new_worker=None, new_lease=None, new_expiry=None):
        if worker != self.worker_id or lease != self.lease_id:
            raise SupervisorError("worker or lease fence mismatch")
        if not isinstance(now, int) or isinstance(now, bool) or now < self.last_time:
            raise SupervisorError("non-monotonic observation time")
        if operation != "stale_recover" and now >= self.lease_expires:
            raise SupervisorError("lease expired")
        if operation == "heartbeat":
            if now <= self.last_time or new_expiry is None or new_expiry <= self.lease_expires:
                raise SupervisorError("heartbeat must advance time and lease expiry")
            self.lease_expires = new_expiry
        elif operation == "stale_recover":
            if now < self.lease_expires or not new_worker or not new_lease or new_expiry is None:
                raise SupervisorError("recovery requires an expired lease and replacement binding")
            self.worker_id, self.lease_id, self.lease_expires = new_worker, new_lease, new_expiry
            self.state = "recovered"
        elif operation == "handoff":
            if not new_worker or not new_lease or new_expiry is None or new_expiry <= now:
                raise SupervisorError("handoff requires a replacement binding")
            self.worker_id, self.lease_id, self.lease_expires = new_worker, new_lease, new_expiry
            self.state = "handed_off"
        else:
            transitions = {("admitted", "start"): "active", ("active", "cancel"): "cancelling",
                           ("cancelling", "cancel_ack"): "closed", ("active", "handoff"): "handed_off",
                           ("handed_off", "resume"): "active", ("recovered", "resume"): "active",
                           ("active", "complete"): "closed", ("active", "fail"): "failed"}
            if (self.state, operation) not in transitions:
                raise SupervisorError("invalid lifecycle transition")
            self.state = transitions[(self.state, operation)]
        self.last_time = now
        self.sequence += 1
        return self.state

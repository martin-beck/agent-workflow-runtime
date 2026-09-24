#!/usr/bin/env python3
"""Executable local façade over the AR-0062 scheduler reference model."""
import copy
from dataclasses import asdict

from scripts.durable_scheduler import Job, Resources, Scheduler, SchedulerError


class RuntimeSchedulerError(ValueError): pass
class RuntimeScheduler:
    def __init__(self): self.scheduler=Scheduler(Resources(cpu=4,memory=8,disk=8),max_concurrency=2,lease_seconds=10,max_queued=32,tenant_limits={"default":2})
    def submit(self, operation_id, job_id, dependencies=(), priority=50):
        try: return self.scheduler.admit(operation_id,Job(job_id,tuple(dependencies),priority=priority,max_attempts=2))
        except SchedulerError as exc: raise RuntimeSchedulerError(str(exc)) from exc
    def dispatch(self, operation_id, worker_id, now):
        try: return self.scheduler.dispatch(operation_id,worker_id,now)
        except SchedulerError as exc: raise RuntimeSchedulerError(str(exc)) from exc
    def complete(self, operation_id, job_id, worker_id, lease_id, now):
        try: return self.scheduler.complete(operation_id,job_id,worker_id,lease_id,now)
        except SchedulerError as exc: raise RuntimeSchedulerError(str(exc)) from exc
    def fail(self, operation_id, job_id, worker_id, lease_id, reason, now):
        try: return self.scheduler.fail(operation_id,job_id,worker_id,lease_id,reason,now)
        except SchedulerError as exc: raise RuntimeSchedulerError(str(exc)) from exc
    def snapshot(self):
        jobs={job_id:{key:value for key,value in asdict(job).items() if key not in {"resources","retryable"}} | {"resources":asdict(job.resources),"retryable":sorted(job.retryable)} for job_id,job in self.scheduler.jobs.items()}
        return {"jobs":jobs,"events":copy.deepcopy(self.scheduler.events),"fence":self.scheduler.fence,"now":self.scheduler.now,"execute":False,"network":"disabled","provider":"not_performed"}

# AR-0139 autonomous chaos and restart qualification

AR-0139 qualifies the composed autonomous run path with deterministic local
agent and Coordinator fakes. The normative scenario list and fail conditions
are in `specifications/autonomous-chaos-restart-v1.json`. The focused
end-to-end regression is `tests/test_autonomous_chaos_ar0139.py`.

The qualification runs a two-task graph that deliberately assigns both tasks
to one exclusive worktree. It checks repeat-run idempotency, one authoritative
terminal reconciliation per task, the ordered AWQ/AWG/UI decisions, and an
unchanged durable state projection after restart/replay. A second run injects
a Coordinator response loss after its terminal `done` write: recovery must
correlate authoritative terminal state with all three durable decisions
before completing the runtime journal. A hostile variant withholds that gate
evidence and verifies that the runtime cannot promote the task to success.

The rest of the fault matrix is exercised by the existing composed boundary
tests:

| Failure surface | Qualification evidence |
| --- | --- |
| Worker crash, timeout, output exhaustion, descendant cleanup | `tests/test_worker_monitor.py`, `tests/test_agent_session.py` |
| Lease expiry, checkpoint binding, retry exhaustion | `tests/test_autonomous_orchestrator.py`, `tests/test_worker_monitor.py`, `tests/test_checkpoint_recovery.py` |
| CAS, ambiguous authority write, idempotency and stale fence | `tests/test_durable_coordinator.py`, `tests/test_execution_controller.py`, `tests/test_autonomous_chaos_ar0139.py` |
| Lost, malformed, duplicate, stale, oversized or out-of-order interaction | `tests/test_interactive_session.py`, `tests/test_session_events.py` |
| UI cancellation/rejection and incomplete authority gates | `tests/test_worker_control_loop.py`, `tests/test_autonomous_orchestrator.py` |
| Sandbox denial and bounded resources | `tests/test_host_sandbox.py`, `tests/test_execution_controller.py` |
| Worktree contention and deterministic restart replay | `tests/test_autonomous_chaos_ar0139.py`, `tests/test_ci_complex_project_workflow.py` |

Run the complete offline suite with `python3 -m unittest discover -s tests -v`.
The suite does not contact a provider or inspect configured credentials, keys,
or models. Its result is offline qualification only: it does not establish
host power-loss guarantees, hosted authority availability, provider behavior,
production resource isolation, remote verification, or release readiness.

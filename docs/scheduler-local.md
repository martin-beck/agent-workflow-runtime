# Local durable scheduler

The runtime exposes a deterministic local scheduler for provider-free
qualification:

```text
awr schedule-submit --state-file ./state/scheduler.json --job-id JOB-A --project alpha
awr schedule-dispatch --state-file ./state/scheduler.json --worker WRK-ONE
awr schedule-complete --state-file ./state/scheduler.json --job-id JOB-A \
  --worker WRK-ONE --lease LSE-00000001
```

The state is atomic and file-locked. Dependencies, bounded concurrency,
priority selection, retry limits, lease IDs, and worker fencing are enforced.
It schedules local mock work only and does not launch providers or replace
Coordinator authority.

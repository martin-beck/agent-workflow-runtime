# Privacy-safe observability

The local runtime can record digest-only audit events:

```text
awr audit-record --home /tmp/awr-home --event-id EVT-ONE \
  --task-id AR-0107 --task-revision 1 --category runtime \
  --status started --detail 'local mock'
awr audit-status --home /tmp/awr-home
```

The journal is bounded and hash chained. Raw prompts, transcripts, tokens,
credentials, private paths, host identifiers, and oversized details are
rejected rather than redacted ambiguously. The journal is local diagnostics,
not Coordinator state or a quality/guidance decision authority.

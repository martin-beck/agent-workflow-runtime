# Local authority transport

`scripts/local_authority_transport.py` provides deterministic in-process
request/event exchange for Coordinator/AWC, AWQ, AWG, and UI fixtures. The
endpoint response is supplied by the authority fixture; the runtime client
cannot manufacture approval or guidance. Transient unknown outcomes are
retried only within an explicit bound and remain blocking when exhausted.

```text
python3 -m unittest tests.test_local_authority_transport
```

This is local conformance evidence. It does not establish a live authority,
network, provider, credential, or durable-state connection.

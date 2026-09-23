<!-- Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved. -->

# Runtime specifications

Every design or conceptual decision in this project must have a versioned,
machine-readable specification under this directory before implementation or
oracle selection. Each specification must have an autonomous positive and
negative checker, an explicit limitation section, and a result bound to the
exact task revision and specification digest.

Specifications are contract evidence, not implementation-refinement proofs.
They must not contain credentials, private paths, prompts, transcripts, host
identifiers, or unbounded command output.

## AR-0001 admission checker

`runtime-charter-v1.json` is the v1 runtime charter, authority matrix, and
specification-before-implementation admission rule. Its canonical UTF-8 JSON
bytes are identified by `sha256:` plus a lowercase SHA-256 digest. An admission
envelope must bind that digest and the current Coordinator task revision, and
must contain unique evidence identifiers and digests.

Run the checker from the repository root with Python's standard library:

```text
python3 scripts/check_admission.py \
  --spec specifications/runtime-charter-v1.json \
  --admission specifications/fixtures/admission-ar0001-v1.json \
  --expected-revision 5
```

The checker is offline and fail-closed. It validates shape, authority-domain
ownership, revision/digest binding, evidence replay, and prohibited private
data in the envelope. It does not verify Coordinator or AWQ state, prove
implementation refinement, enforce process isolation, or establish hosted
CI, provider, GitHub, or remote runtime success. Those authorities remain
external to this repository and must be evidenced separately.

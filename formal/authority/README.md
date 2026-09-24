# AR-0099 TLA+/TLC authority model

`AuthorityInteraction.tla` is the executable TLA+ model for the mandatory
AWC/Coordinator, AWR, AWQ, AWG, and Agent Workflow UI boundaries defined by
AR-0098. `AuthorityInteraction.cfg` fixes two concurrent jobs and one bounded
repair attempt and checks safety over their interleavings.
`AuthorityInteractionLiveness.cfg` fixes one job and the same repair bound to
check conditional terminality under weak fairness. This deterministic split
retains concurrent-job coverage without multiplying the fairness state space;
the safety configuration constrains the two-job cross-product to the shared
admission/lease/dispatch/evidence path. The full one-job fairness run still
checks the normal terminal path. `AuthorityInteractionChange.cfg` and
`AuthorityInteractionRepair.cfg` separately bound the required-change and
exhausted-repair branches, including AWG→UI routing and fail-closed outcomes.
The four configurations together cover the full transition relation without
letting unrelated cross-products make CI nondeterministic.

The model includes:

- AWC-only admission, lease issuance, revision-advancing recovery, and
  terminal commit;
- AWR dispatch, execution, evidence, checkpoint, retry/repair, and escalation;
- AWQ acceptance before continuation or completion;
- AWG routing of material alternatives and every refinement, test, or
  specification change to the UI decision interface;
- fail-closed rejected, ambiguous, and expired UI outcomes; and
- bounded repair exhaustion that cannot resume until AWG and UI have completed.

The JAR is repository-local and pinned by SHA-256. It was copied from the
pre-existing local tool cache; no network fetch is part of this AR. The only
supported invocation is:

```bash
python3 scripts/check_tlc_authority.py
```

The runner invokes exactly:

```text
java -cp formal/authority/tla2tools.jar tlc2.TLC \
  -config formal/authority/AuthorityInteraction.cfg \
  formal/authority/AuthorityInteraction.tla
```

The runner executes that command once with each checked-in configuration. All
four runs are mandatory; there is no option to omit a scenario.

Missing Java, a missing JAR, a digest mismatch, TLC failure, or a missing TLC
success marker is a hard failure. There is no download fallback, skip path, or
Python-model fallback. Every invocation receives a temporary `-metadir`, which
is deleted after the run; no TLC states or traces are written to the checkout.
`TLA_TOOLS_JAR_URL` is deliberately ignored. The
Python AR-0098 model remains a separate executable refinement oracle; passing
it does not satisfy this TLC check.

The JSON fixtures under `specifications/fixtures/` provide deterministic
positive and hostile trace obligations. They are checked against the AR-0098
event vocabulary by tests; they do not replace TLC's transition-system check.

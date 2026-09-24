# Mandatory authority gates

Executable admission consumes Coordinator, AWQ, AWG, and UI observations in
that order. A rejected or stale result stops the workflow; the runtime cannot
turn an observation into an acceptance. UI is required even when the guidance
fixture reports `approved`, which prevents a worker or ambiguous interpretation
from skipping the human decision process.

`awr authority-admit` uses deterministic local endpoints for CI conformance.
Those endpoints prove control flow and revision fencing only; they are not a
live Coordinator, AWQ, AWG, or UI service and the result remains
`authority_state=observed_only`.

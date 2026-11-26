# One jointly calibrated23-rule censor

This lab classifier combines15 existing two-second window rules,6 whole80s
per-TCP-flow features and2 capture-order count signatures. It uses one OR margin
across every declared window/flow/reconnect, calibrated jointly to both empirical
session-group and direct-rule-hit TCP-flow FPR budgets of5% on train/validation.
It never gives each component a separate5% budget.

Cross-direction timestamp ambiguity masks logical adjacency r05/r06/r10/r15 and
whole-flow LF05. Length/count and valid within-direction timing remain usable.
The two companion signatures retain the observable capture-order view: they sort
the same earliest64 selected records by original completion ordinal, then count
alternation/equal opposite neighbors. They invent no timestamps or physical order.

The executable checks its own SHA and pins the score engine, observer contract,
long-flow definitions and combined catalog. Event nanoseconds decode as int64.
Malformed masks/ordinals, conflicting metadata, missing/censored calibration
reports and sealed-test references fail closed. Diagnostic qualification groups
cannot enter B1 fitting. Empty evidence/disabled classifiers remain explicit;
abstention is not a stealth result.

```sh
./ensemble catalog -engine PINNED_CLASSICAL -ordering-sha PINNED_ORDERING_SHA -out catalog.json
./ensemble fit -index B1_INDEX -freeze B1_PROJECTION -engine PINNED_CLASSICAL -out policy.json
./ensemble evaluate -index B2_INDEX -freeze B2_PROJECTION -engine PINNED_CLASSICAL -policy policy.json -out evaluation.json
```

Full-flow observations reuse actual TCP flow IDs, so they do not inflate the flow
population. Physical-session metrics and source-workload cluster OR are separate;
replicas sharing a plan/origin/stack are not proven independent samples. Reported
flow FPR excludes collateral blocking caused by a persistent endpoint ban. This
program performs offline classification; live enforcement is a separate test.

Validation includes23-way OR inflation, high-fanout direct-flow constraints,
partial-order masks and capture-order companions, exact raw timestamp/ordinal
provenance, no-TLS TCP connections, scope conflicts and whole-flow applicability.
No real B data is fitted by tooling preparation.

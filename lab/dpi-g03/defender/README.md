# G03 primary session OR defender

This tool reuses the pinned existing15-rule `classical` executable for raw scores.
No feature formula is copied. It calibrates one OR across **all declared primary
windows, rules, TCP flows and reconnects of a group**. Both empirical group FP
and direct-rule-hit TCP-flow FP must be≤5% on benign train **and** validation.
High-fanout connections cannot hide behind a low group FP. IP-ban collateral and
actual30s enforcement are separate measurements, not this direct flow metric.

The selected features remain2s/max64-record hypotheses. The policy lists the
exact80s schedule and flow prefixes; it is not continuous DPI of every instant
or a full80s feature model. Raw PCAP remains available for later feature work on
B1 train/validation before B2 freeze. No real B data is fitted by tooling checks.

## Inputs and commands

```sh
go build -trimpath -o out/dpi-g03/tooling-defender/classical ./lab/dpi-v2/classical
go build -trimpath -o out/dpi-g03/tooling-defender/defender ./lab/dpi-g03/defender
out/dpi-g03/tooling-defender/defender fit \
  -freeze DEFENDER-B1.json -index B1-INDEX.json \
  -engine out/dpi-g03/tooling-defender/classical -out POLICY.json
out/dpi-g03/tooling-defender/defender evaluate \
  -freeze DEFENDER-B1.json -index B1-INDEX.json \
  -engine out/dpi-g03/tooling-defender/classical -policy POLICY.json -out DEV.json
# B2 is a NEW collection, after the exact final policy was frozen.
out/dpi-g03/tooling-defender/defender evaluate \
  -freeze DEFENDER-B2.json -index B2-INDEX.json \
  -engine out/dpi-g03/tooling-defender/classical -policy POLICY.json -out TEST.json
```

A defender freeze is a **projection** of the collection contract, with its own
SHA256. `collector_freeze_sha256` pins the runtime's master freeze carried by
observer metadata; the master freeze can retain its existing JSON shape.
`EXAMPLE-B1-freeze.json`, `EXAMPLE-B2-freeze.json` and typed index examples are
under tooling. Placeholder SHAs deliberately fail validation.

B1 projection: schema3, stage`B1`, only declared train/validation assignments,
source/engine/observer/catalog pins,80s primary/82s capture/2s grace, frozen window
schedule, both5% budgets and30s declared cooldown. Dynamic ordered offsets are
read from the freeze, not a hardcoded four-window schedule. Current protocol is
`[0,8,16,24,32,40,48,56,64,72,78]`, each2s.

B2 projection: stage`B2`, **test assignments only**, exact
`development_freeze_sha256` of the B1 defender projection and `policy_sha256`.
B2 freeze UTC must follow policy UTC. Every known test capture must begin after
both. Policy UTC must follow the latest development capture. Previously recorded
test cannot be relabeled fresh. B1 evaluation stays explicitly development.

Typed index:

```json
{"schema":3,"stage":"B1","reports":[
  {"group_id":"GROUP","split":"train","path":"GROUP-observer.json"}
]}
```

Paths are relative to the index. The **whole index is preflighted before opening
any report or invoking the score engine**. A B1 test reference is rejected,
never silently skipped. B2 fitting is rejected. Missing/failed declared captures
stay in the cohort as incomplete groups; they cannot disappear from denominators.
`coverage_errors` may be supplied on the index or a report reference for external
collector accounting/UTC/censor failures that the PCAP parser cannot infer.
Application/nonce failures remain separate functional scope, not capture errors.
Incomplete B1 calibration aggregates every group failure and rejects before
scoring/fitting, preserving `.rejected.json`. B2 reports incomplete observations
as unknown, with any valid observed hit kept separately.

## Assignment and observer contract

Every frozen assignment has core`group_id/split/class/profile` plus
`source_workload_id`, `scope:"primary"`, `transport`, and`client_stack`.
Paired source-workload IDs may repeat across classes **within one split**; any
cross-split pair is rejected. Group IDs remain distinct physical deployments.
Primary benign must declare`transport:"ordinary-tls"`; primary BelNet positive
uses`"reality"`. REALITY with another payload is diagnostic, rejected from this
primary calibrator rather than counted as ordinary benign FP.

Extra assignment labels are joined from the frozen contract by verified core
metadata; the observer need not export those labels. They are not score features.
No IP/port/SNI/profile/class/source-ID enters the15 score formulas.

Observer input must be schema3/version`g03-observer-v1`, exact collector freeze
SHA and explicit prelaunch VM`measurement_start_unix_micros`. Full80s coverage
and actual2s grace are checked. Initial bootstrap **inside** this interval is
PRIMARY, as are subsequent flow prefixes. A genuinely premeasurement
`bootstrap-prefix` marks the B group incomplete: it cannot hide a difficult
initial handshake. Grace-only flows create no new primary obligations. Per-flow
fixed-window slots and in-horizon prefixes are checked against the flow inventory.
Host lifecycle time is never silently treated as VM time.

## Outcomes and limits

Reports retain per-window scores/hits, group decisions, source report SHAs,
client/profile/split metrics and coverage errors. `enabled_rules` counts
individual cutoffs; `effective_rules` also accounts for the joint margin. An
empty or mathematically all-disabled classifier explicitly abstains. Evidence
only for disabled rules also abstains. Sparse/inadequate evidence, missing
capture and a genuine scored nondetection are different statuses.

With incomplete groups, overall observed detection rates are lower bounds,
not successful stealth or population FP estimates. Complete and incomplete
benign/positive counts and complete-group FPR are separate. Rule-hit group OR is
descriptive offline persistence; firewall cooldown and collateral blocking are
not simulated. Positive labels establish a transport attempt, not native UDP or
nonce delivery: join those external proofs separately.

Validation uses fixtures only: pinned engine CLI round-trip, both joint budgets,
high-fanout regression, dynamic offsets, test preflight, B2 chronology, missing
and censored groups, bootstrap inclusion, grace exclusion, disabled/evidence
abstentions and deterministic tied cutoffs. G01 source and binaries are unchanged.

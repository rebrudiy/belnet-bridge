# Fifteen explicit DPI hypotheses

This detector uses deterministic predicates over TLS record lengths, direction
and arrival time. It contains no forest or learned weights. Fifteen declared
rules produce fifteen cumulative policies; they are hypotheses, not fifteen
successful transport improvements. The transport experiment coordinator pairs
each policy with independently recorded native BelNet traffic.

| Rule | Observable signature |
|---|---|
| r01–r02 | One dominant uplink/downlink length |
| r03 | Same dominant length in both directions |
| r04 | Low length entropy |
| r05 | Strict request/reply direction alternation |
| r06 | Equal lengths of opposite-direction neighbors |
| r07–r08 | Regular uplink/downlink intervals |
| r09 | Alignment with a fixed timing grid |
| r10 | Consistently immediate replies |
| r11 | Narrow uplink padding range |
| r12 | Two dominant lengths |
| r13 | Frequent small uplink records |
| r14 | Symmetric byte volumes |
| r15 | Fixed-size alternating traffic sustained across time bins |

The exact formulas, minimum evidence and proposed transport response are in
`catalog.json` and every policy. Each score is 0–1; insufficient records abstain.
The data window is 2 seconds and at most 64 records. No IP, SNI, plaintext, profile
or endpoint identity enters a score. Provenance fields enforce splits and report
results by workload; they do not select a threshold.

## Calibration and freeze

Thresholds are determined only by benign train and benign validation records.
Positive observations supply detection metrics. Every cumulative OR policy is
calibrated again: individual 5% rules cannot silently become a 75% union. Both
flow FPR and whole-group FPR must stay ≤5% on calibration splits. Tied scores are
handled conservatively. Small group counts can force zero allowed group hits.

Test events and labels are discarded before fitting. Shared source groups
across splits are rejected. The exact calibration-only input is saved beside
the policy, together with a content hash. Use separate output files per round;
freeze before evaluating test and retain every failure.

```sh
go run ./lab/dpi-v2/classical catalog -output out/dpi-v2/classical/catalog.json
# Input for round k: unchanged controls + core + positive rounds up to k.
go run ./lab/dpi-v2/classical fit -rules 5 -input ROUND5.json -output POLICY5.json
go run ./lab/dpi-v2/classical evaluate -policy POLICY5.json -input ROUND5.json \
  -split test -output RESULT5.json
```

Use `-rules 15` for the final stronger check.
Evaluation does not modify the policy. Reports include TP/FP/TN/FN, coverage,
flow and group denominators, per-profile metrics, rule hits and raw scores.
Zero observed FPR in a small, correlated sample is not a population guarantee.

## Separate checks and limits

`evaluate -offset 5000000` or 10000000 evaluates a late 2-second window with the
same frozen thresholds. Supply full traces or matching pre-extracted late
observations; absent late data abstains and must not be presented as a bypass.

TLS type 23 includes encrypted TLS 1.3 handshake records. These inputs cannot
isolate handshake fingerprints, JA3, SNI or certificates. Reports explicitly mark
that check unevaluated. This is an offline detector; it does not itself close
connections. Live blocking, 30-second reconnect persistence, invalid credential
probes and BelNet UDP socket continuity need separate runtime evidence.

Validation: `go test -race ./lab/dpi-v2/classical` and
`go vet ./lab/dpi-v2/classical`. Tests cover group leakage, test independence,
all fifteen joint FP budgets, score ties, prefix policies and late-window bounds.

# Auxiliary ML verifier — separate from classical23

This tool reuses the unchanged Go`internal/traffic` CART forest and its fixed
80-feature extractor. No new feature vector, capture-order fork, parameter sweep
or physical-causality claim is introduced. Primary evaluation remains classical23.
Actual R2/Q/test or new R3 data was not read while preparing this tooling; all
training/checks here use synthetic fixtures.

## Fixed experiment

- Seed2026111907,128 trees, depth8, minimum16 canonical records/window.
- The existing80 ciphertext length/direction/time features; max64 records/2s.
- Same prelaunch80s windows/reconnects and ordering SHA as observer-v2.
- Entire ordering-ambiguous windows abstain, because the existing vector mixes
  order-sensitive and size features. No silent zero-imputation of masked fields.
- Train the forest on TRAIN only. Then choose one strict`score > threshold`
  cutoff satisfying group-OR and actual-TCP-flow-OR FP≤5% on benign TRAIN and
  benign VALIDATION, jointly across all windows/reconnects.

The library's initial per-window threshold is replaced by this joint threshold;
it is not a separate detector OR. Test never selects features/model/threshold.
This auxiliary has its **own** empirical budget. OR with classical does not
inherit5%. A valid auxiliary detection can refute a blanket bypass claim even if
classical misses; small correlated cohorts still do not prove population FPR.

Metadata IDs, group/source labels, split, profile and client stack are excluded
from the feature vector. They enforce provenance/splits and report support.
Capture-time representation is sensor-conditioned, not physical request/reply
causality. Existing feature code's nonnegative-gap handling is never used to
repair malformed input: raw/canonical time validation rejects it first.

## CLI and data-release gate

```sh
go build -trimpath -o out/dpi-g03/auxiliary-ml/tooling/auxiliary ./lab/dpi-g03/auxiliary-ml
out/dpi-g03/auxiliary-ml/tooling/auxiliary catalog -out CATALOG.json
# Only after explicit full-cohort completion/quality release:
out/dpi-g03/auxiliary-ml/tooling/auxiliary fit \
  -freeze AUX-B1.json -index OBSERVER-INDEX.json -out AUX-POLICY.json
out/dpi-g03/auxiliary-ml/tooling/auxiliary evaluate \
  -freeze AUX-B1.json -index OBSERVER-INDEX.json -policy AUX-POLICY.json -out DEV.json
# Fresh sealed B2 is collected AFTER the final auxiliary policy freeze:
out/dpi-g03/auxiliary-ml/tooling/auxiliary evaluate \
  -freeze AUX-B2.json -index SEALED-INDEX.json -policy AUX-POLICY.json -out TEST.json
```

Model/report overwrite is refused. A separate schema1 auxiliary freeze projection
pins collector/observer/binary/library/feature/ordering hashes, fixed parameters,
assignments, schedule and a data-release JSON SHA. It can share the ensemble's
schema4 typed index;`longflow_path` is ignored and never opened.

The release is checked **before even opening the index**:

```json
{
  "schema":1,
  "role":"auxiliary-data-release",
  "stage":"B1",
  "collector_freeze_sha256":"ACTUAL_NEW_COMPLETE_COHORT_SHA256",
  "issued_at":"UTC_AFTER_CAPTURE_COMPLETION",
  "acquisition_finished":true,
  "read_authorized":true,
  "fit_authorized":true
}
```

Example templates under tooling default both authorizations tofalse and contain
invalid placeholder hashes. Preparation does not authorize real reads/fitting.
The release must target the NEW completed cohort after its quality gates clear;
the incomplete24/71 R2 checkpoint is not training input. Missing/censored declared
groups stop calibration, with all failures preserved. Q/development/diagnostic and
test assignments are rejected from B1 before report I/O. Cross-split paired source
workloads are rejected; optional metadata may be absent but cannot contradict
frozen provenance. Raw int64 timestamps,1-based globally consistent ordinals and
explicit ordering masks are checked by the reused reviewed input contract.

## Policy/B2 adapter ABI

Policy top-level names match the classical timestamp/provenance convention:
`policy_frozen_at`, `last_development_capture_ended_utc`, `freeze_sha256` (the exact
**auxiliary B1 projection SHA**). Additional pins:
`feature_definitions_sha256`, `library_source_sha256`,
`ordering_semantics_sha256`; model fields`hyperparameters`,
`joint_group_flow_threshold`, `disabled`, `disabled_reason`, `model`.

B2 auxiliary projection must reference its own`auxiliary_policy_sha256` and
`development_freeze_sha256`. Its collector freeze follows the final auxiliary
policy; all known test captures follow both. Exact policy validity is checked
before opening the sealed index. Optional B2 gate integration needs an explicit
separate auxiliary descriptor/projection; silently reusing the classical
projection SHA is invalid. No unseal is performed here.

## Honest outcomes

Reports prominently separate class/stack/profile support, eligible group/flow FP,
masked/sparse windows, incomplete groups and classifier-disabled abstention.
Insufficient eligible training groups produces an explicit disabled policy,
not a fabricated model. Majority-unsupported windows/classes are
`AUXILIARY_INCONCLUSIVE`, not a masking success. Raw detections remain visible.
All-abstain/allow-all under a finite FP budget is retained honestly. No actual
firewall/cooldown execution or collateral IP-ban FP is claimed.

Validation covers deterministic synthetic training/model reload, metadata
exclusion, strict data/test release order, raw/schema/mask identity checks,
window-OR inflation, high-fanout direct-flow FP, sparse/disabled/censor outcomes
and future B2 chronology. `go test -race` and`go vet` run on this package;
versioned binaries/source archives and pinned library source hashes are in
`out/dpi-g03/auxiliary-ml/tooling/TOOLING.json`.

# One calibrated OR across the entire session

This command reuses the existing deterministic 15-rule executable for raw scores.
It copies no feature formula and verifies the executable and rule-definition
SHA256 against the fresh Stage B freeze. No forest is involved.

For each rule, calibrate the maximum score over **all windows and reconnects of
one group**, using benign train and benign validation groups. Then jointly
calibrate the maximum threshold excess across **all 15 rules**. Both per-rule
cutoffs and the joint margin constrain group OR and TCP-flow OR together on
train/validation. One group verdict is the OR of every eligible window; it is not
15 separately calibrated detectors. Both frozen empirical FPR budgets are 5%.
Small samples do not prove those rates for other users/networks. Flow FP means
**direct rule-hit TCP flows**, excluding collateral flows blocked by a30s IP ban.
Per-window/flow counts and per-profile coverage are also reported. A useless
all-abstaining detector is not evidence of successful masking.

```sh
go build -o out/dpi-g01/tooling/classical ./lab/dpi-v2/classical
go build -o out/dpi-g01/tooling/defender ./lab/dpi-g01/defender
out/dpi-g01/tooling/defender fit -index TRAINVAL-INDEX.json -freeze FREEZE.json \
  -engine out/dpi-g01/tooling/classical -out POLICY.json
# Collect sealed test only after POLICY.json is frozen.
out/dpi-g01/tooling/defender evaluate -index ALL-INDEX.json -freeze FREEZE.json \
  -engine out/dpi-g01/tooling/classical -policy POLICY.json -out REPORT.json
```

An index is `{"reports":["observer-report.json",...]}`; paths are relative to the
index. One observer report per group. The freeze declares every group assignment.
The fitting index may omit future test paths; all declared train/validation
groups are required. Evaluation requires all declared groups so a failed capture
cannot silently disappear. Train/validation/test of a deployment never separate.

`EXAMPLE-freeze.json` under tooling documents the fields and deliberately uses
stage EXAMPLE: it cannot authorize collection/fitting. Real freeze requires stage B,
explicit StageA `proceed`, source/binary pins, groups and schedule. Capture must
start after that freeze and carry its exact SHA. Model fitting excludes test
before scoring and saves an exact scored calibration snapshot. Its UTC freeze
must precede test capture; previously collected test cannot become a fresh test.

Incomplete calibration groups stop fitting; a `.rejected.json` preserves the
reason and scores. Evaluation distinguishes `incomplete_undetermined`,
`incomplete_positive_observed`, complete abstention and an actual verdict.
Complete sparse windows remain in the denominator. Per-group OR and per-family
coverage are explicit, including any reconnect. Positive class is the supplied
wrapper-attempt label; native UDP/nonce eligibility must be joined separately.

The 30 s cooldown is declared in the policy. This offline tool does not install
firewall rules or establish a real native recovery result. No real collection or
old-test fitting was performed to validate this tooling; tests use fixtures.

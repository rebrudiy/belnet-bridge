# Full80s TLS metadata, six candidate features

```sh
go build -trimpath -o lab/dpi-g03/longflow/tooling/longflow ./lab/dpi-g03/longflow
lab/dpi-g03/longflow/tooling/longflow -pcap GROUP.pcap -meta GROUP-observer-meta.json -out FULL80.json
lab/dpi-g03/longflow/tooling/longflow -catalog -out CATALOG.json
```

This extractor copies the frozen G03 observer parser into a **new** package.
Original observer source/binaries/reports remain unchanged. Explicit prelaunch
VM`measurement_start_unix_micros` and`measured_seconds:80` are required. Capture
bounds, full SYN context,2s completion grace and PCAP parsing semantics stay the
same. Primary time is end-exclusive`[start,start+80s)`. All complete TLS23 records
are processed; there is no64-record cutoff for these aggregates.

**No classifier, fitting or threshold selection occurs.** Six new deterministic
scalar candidates are described below. Final classic15+wholeflow6 must share ONE
joint group-OR and direct-flow calibration budget; do not assign another5% to
these six. Machine learning is not part of this tool.

## Features

Every non-null scalar is in[0,1]; each value has`eligible/support/reasons`.
Coverage and minimum evidence are independent requirements. Numeric values
retained for ineligible observations are diagnostic, not classifier inputs.

| ID | Definition | Minimum evidence |
|---|---|---|
| lf01_exact26_share | Records exactly26 B / all records | 16 records |
| lf02_tiny_le64_share | Records≤64 B / all records | 16 records |
| lf03_length_concentration | 1 − Shannon entropy(exact lengths)/log2(record count) | 16 records, uncensored histogram |
| lf04_duplex_byte_balance | 1 − abs(up bytes−down bytes)/(up bytes+down bytes) | 16 records,≥4 each direction |
| lf05_immediate_reply_share | Within-flow up immediately followed by down within0..10ms / up records | 16 records,≥8 up, no negative adjacency |
| lf06_directional_regularity | Max eligible up/down1/(1+CV positive same-direction gaps) | ≥8 positive gaps and≥200ms summed span in one direction |

Record lengths include the5-byte TLS header. TLS23 may include encrypted
handshake records. A26-byte record is not proof of a4-byte plaintext header,
dummy traffic, native UDP delivery or an obfuscation vulnerability.

Additional raw diagnostics include exact length counts, entropy bits, modal
share, directional transitions, paired latency moments, zero/negative gaps and
positive gap moments in each direction. Population CV uses all positive gaps;
zero gaps are separately counted. A record near the80s boundary can have a reply
outside the scope: its up record remains in the declared denominator. There is
no plaintext request/reply identity assertion.

## JSON contract

Schema1/version`g03-longflow-v1`:

```json
{
  "flow_id": "flow-0000",
  "applicable_to_primary": true,
  "coverage_eligible": true,
  "features": {
    "lf01_exact26_share": {
      "value": 0.25,
      "eligible": true,
      "support": 100,
      "reasons": []
    }
  }
}
```

Read**`flows[].features`** for the six per-TCP-flow candidates. Group verdicts
can OR actual flow decisions alongside classic window decisions; do not create
a pseudo-flow FP denominator from`group.features`. The latter are diagnostics.
Group transitions, pairs and gaps pool **within-flow** counts; records on two
different entries are never made into an adjacent pair. Native SID, nonce,
source-workload IDs, fixed entry counts and payload identity are not features.
Tuple/group/class fields are provenance for joins, not scalar inputs.

Output also includes primary UTC bounds, PCAP SHA, feature-definition SHA,
parser baseline source SHA, before/inside/after record counts, per-flow coverage,
clock diagnostics and resource limits. Sparse/invalid/censored is not nondetection
or stealth. External capture accounting, native UDP and end-to-end proof joins
remain separate. The executable never reads a dataset index or a fitted policy.

## Bounds and strict clock baseline

Exact histogram limits:1024 distinct lengths/flow,4096 for group diagnostics,
16384 retained entries globally across those maps. On overflow, omitted records
are explicitly counted and entropy/concentration becomes ineligible. Fraction,
byte and timing counters continue. Flow tracking is bounded512; core limits stay
256MiB PCAP,8MiB pending TCP bytes globally,256KiB/stream and256 segments/stream.
The copied core retains at most64 metadata records per sampled window for its
coverage contract, while aggregate counters consume every completed record.
No application/TLS payload is exported or retained for in-order streams.

File order is unchanged. Record completion uses maximum constituent/contiguous
availability UTC. Cross-flow timestamp reorder is diagnostic. This version keeps
frozen G03's **strict same-flow** rejection, including opposite-direction file
ordering reversals; no tolerance, clamping or retrospective repair is introduced.
A future semantics version must remain separate and document uncertainty.

```sh
go test -race ./lab/dpi-g03/longflow
go vet ./lab/dpi-g03/longflow
```

Fixtures cover30000 records across80s and outside sampled windows, exact end
boundaries, bounded histogram/flow memory, no cross-flow pairing, deterministic
metadata-only output,16µs cross-flow skew, strict cross-direction failure and
pending-segment causal completion. Original G03 fixtures are also retained.
Tooling manifest and versioned Darwin/LinuxARM64 binaries live in`tooling/`.
Only synthetic fixtures were processed while developing this version; actual B
data was not read and no feature threshold was chosen.

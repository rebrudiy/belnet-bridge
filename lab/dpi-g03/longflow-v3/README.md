# G03 longflow V3

```sh
go build -trimpath -o lab/dpi-g03/longflow-v3/tooling/longflow ./lab/dpi-g03/longflow-v3
lab/dpi-g03/longflow-v3/tooling/longflow -pcap GROUP.pcap -meta GROUP-meta.json -out FULL80.json
lab/dpi-g03/longflow-v3/tooling/longflow -catalog -out CATALOG.json
```

NEW schema3/version`g03-longflow-v3`, using observer-V3 directional causal
semantics. Strict V1 is unchanged. Full80s scalar definitions and histogram bounds
are retained, with explicit LF05 ordering eligibility. No classifier/fit/threshold
selection or acquisition is performed.

Six per-flow candidates remain exact26 share, tiny≤64 share, length
concentration, duplex byte balance, immediate adjacent reply share and directional
gap regularity. Values are[0,1] or null, with`eligible/support/reasons`. Lengths
include the5-byte TLS header; TLS23 may include encrypted handshake.

`flows[].ordering_ambiguous` and`masked_features` identify ambiguous bidirectional
record order, including raw/projected timestamp ties and source file/time
reversals. `masked_features` is exactly`["lf05_immediate_reply_share"]` when
ambiguous, else`[]`; LF05 becomes ineligible. Raw diagnostic value is not an
admissible score. Length/count features and sound same-direction gap features
can remain eligible. Genuine directional clock, gap, conflict and capture
failures remain invalid.

Fullflow ambiguity is tracked over all primary records. Group transition/pair/gap
statistics pool within-flow observations only; no pairing across entries or use
of nativeSID/nonce/source-ID. Group features remain diagnostics, not a pseudo-flow
FP denominator. Read`flows[].features` for ensemble inputs. The final combined
classic/window/wholeflow detector and any declared companion features require
ONE joint groupANDactual-flow FP budget, not separate per-family budgets.

The report pins `ordering_semantics_sha256` and the new feature-definition SHA.
The unchanged scalar score formulas must not silently bypass these masks.
Two bounded PCAP passes discover exact minimum flow-prefix anchors; raw packet
order/timestamps are untouched. Full80 aggregates consume every completed TLS23
record, independently of64-record sampled-window selection.

Bounds:1024 distinct length bins/flow,4096 group bins,16384 entries globally;
censoring explicitly disables concentration, while exact counters continue.
Parser bounds remain512 flows,256MiB PCAP and8MiB pending TCP bytes globally.
No application payload is exported. External capture accounting and native
end-to-end proof eligibility still require separate joins.

Tests cover30000/full80 records, memory caps, directional causality, ambiguous
order/ties, earliest64 logic, deterministic metadata and selective masking:
LF01/02/03/04/06 can remain admissible when only LF05 ordering is ambiguous.
Original V1 reports and the failed B1 checkpoint are not reclassified as passes.

Reporters also accept `split:"development"` for Q diagnostic captures. This does
not authorize classifier fitting: the ensemble/fitter retains its strict
train/validation/test gates. Unknown split strings remain rejected.


## Coverage V3

`coverage_semantics_sha256` pins [coverage-contract.json](coverage-contract.json).
Each flow exports `raw_tcp_payload_bytes_including_retransmits`, `primary_scope`,
`setup_state`, captured SYN/SYNACK, RST and FIN. The payload counter includes
SYN/TFO data and retransmissions before any handshake/reassembly branch. It is
a count only; no payload is exported.

A captured initial SYN with exactly zero TCP payload can lack SYNACK without
being called capture loss. Its state is `setup_incomplete_no_tls_evidence`: an
observed incomplete setup, with no inferred cause and no DPI evidence. ACK-only
or RST-only without initial SYN remains UNKNOWN. Any payload with missing
handshake remains UNKNOWN, including ClientHello and SYN/TFO data. TCP gaps,
causal clock errors, malformed or censored capture remain strict.

`zero_payload_setup_only=true` allows a null TLS anchor only with an explicit
primary start, at least one SYN inside primary and captured SYN/zero raw payload
for every primary-scope flow. No TLS anchor or feature is fabricated. Actual
primary flow identities remain in the denominator, with sparse/unsupported
evidence separated from a negative classifier verdict. Grace-only attempts
create no primary obligation and cannot waive no-activity UNKNOWN.

V1/V2 sources, reports and binaries are unchanged. Ordering masks and the six
longflow scalar definitions are unchanged. Synthetic tests only; no traffic or
actual cohort fitting.

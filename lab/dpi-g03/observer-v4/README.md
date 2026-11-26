# G03 observer V4: directional causality and explicit order masks

```sh
go build -trimpath -o lab/dpi-g03/observer-v4/tooling/observer ./lab/dpi-g03/observer-v4
lab/dpi-g03/observer-v4/tooling/observer -pcap GROUP.pcap -meta GROUP-meta.json -out WINDOWS.json
```

NEW schema5/version`g03-observer-v4`. V1 source, binaries and reports remain
immutable. Explicit R2 metadata declares the common prelaunch VM80s primary,
82s capture/grace2 and fixed offsets0/8/16/24/32/40/48/56/64/72/78, each2s.
Initial and reconnect prefixes inside primary remain PRIMARY; grace-only flows
create no extra obligations. Full capture preserves SYN/bootstrap context.

## What changed

TCP and complete-TLS-record timing remains strict **within each direction**.
Unresolved gaps, conflicting overlap, malformed/censored data and genuine
same-direction clock reversal remain invalid. A file/time reversal between the
two independent directions is diagnostic, not proof of TCP/TLS causal failure.
Record completion still uses maximum constituent/contiguous-availability UTC.
No PCAP sorting, timestamp clamping, tolerance or clock-error bound is introduced.

All extraction uses two bounded seekable-PCAP passes: discover the true minimum
complete TLS23 UTC for each flow and the group, then construct exact windows.
This avoids anchoring a prefix on the first file callback when another direction
contains an earlier record. Phase-fixed windows remain at explicit VM offsets.
No full packet trace or application payload is retained.

Per window, every completed record is counted; earliest64 metadata events by
`(raw_ns,ordinal)` are retained using bounded insertion. Output`at_micros` is
nondecreasing for the unchanged classic engine. Additional event fields:

- `raw_ns`: absolute record completion UTC, unchanged by metadata ordering.
- `ordinal`: globally unique1-based TLS23 completion callback order during
  original PCAP file processing. Multiple records in one packet each get an
  ordinal. Repeated windows reference the same event ordinal. It is a
  sensor/decoder completion order, not physical wire or first-byte order.

A stable metadata tie break does not prove a physical direction order.
`ordering_ambiguous` is true for opposite-direction completed-record file/time
reversal, equal raw timestamps, or equal projected microseconds. Ambiguity is
tracked over **all** records in the window, including records beyond64.
ACK-only packet reorder alone does not imply TLS-record ambiguity.

When ambiguous, `masked_rules` is exactly`["r05","r06","r10","r15"]`; otherwise
it is`[]`. `ordering_ambiguity_reasons` records the cause. Length/count rules and
sound directional timing can remain usable. Genuine stream/capture failures are
not rescued by these masks.

## Consumer contract

Top`ordering_semantics_sha256` pins `ordering-contract.json` canonical bytes
without its trailing newline. Old scalar formulas remain pinned unchanged.
A NEW ensemble adapter must remove masked scores **before** calibration and
decisions; retaining them as admissible scores with a warning is invalid.
Raw suppressed scores may remain diagnostics. Frozen policy definitions bind
this mask semantics SHA plus score/catalog/source pins.

Old G03 defender schema3 is intentionally incompatible. Use the new ensemble
loader with explicit mask validation. Group coverage, rule evidence eligibility
and order-sensitive-rule admissibility are different fields. No mask outcome
is a stealth, native-delivery or ISP result.

Existing bounds remain:512 flow instances,256MiB PCAP,8MiB pending globally,
256KiB/stream,256 segments/stream,1MiB captured packet,64 selected events/window.
Tests include raw/projected ties, ties beyond the64 boundary, true-minimum
prefixes, earliest64 replacement, same-packet unique ordinals, genuine stream
failure and unresolved gap/conflict rejection. No real B fitting occurs here.

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

## V4 bug fix: primary handshake inventory

Schema remains5, with version`g03-observer-v4`. Coverage SHA5591ec remains
unchanged because it already declares strict missing-handshake payload behavior.
Before publishing windows, every actual primary-scope flow with any raw TCP
payload and missing captured initial SYN or SYNACK makes group coverage UNKNOWN
(`primary_payload_with_missing_handshake`). This catches short ClientHello/TFO
attempts wholly between fixed windows even when a different flow supplies the
TLS23 anchor. Zero-payload captured-SYN abstention is unchanged. Grace-only
attempts create no new primary obligation. No timing, mask or scalar formula
changes; V3 source/manifests/binaries/reports remain unchanged. Every recorded genuine primary-scope flow fault with issue timestamp before
primary end also makes group coverage UNKNOWN, independently of sampled windows
and TLS23 presence. This includes gaps, conflicts, missing initial SYN, malformed
TLS, captured-close partial records and per-stream causal clock errors.
Top-level primary-fault reasons preserve sound earlier window observations for
observed-hit lower bounds; they never permit calibration on the incomplete
group. Causal diagnostics use their actual occurrence timestamps, with no
clamping/sorting/tolerance; postprimary faults alone create no new obligation.
A closed partial record is qualified at its captured close rather than an
unrelated flow's global last-packet time. Absence of a recorded fault is not
proof of capture completeness; external capture accounting remains required.

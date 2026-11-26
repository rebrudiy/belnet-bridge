# G03 observer V2: directional causality and explicit order masks

```sh
go build -trimpath -o lab/dpi-g03/observer-v2/tooling/observer ./lab/dpi-g03/observer-v2
lab/dpi-g03/observer-v2/tooling/observer -pcap GROUP.pcap -meta GROUP-meta.json -out WINDOWS.json
```

NEW schema4/version`g03-observer-v2`. V1 source, binaries and reports remain
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

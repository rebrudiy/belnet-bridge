# G04: classical censor over available TLS headers

This is a new, explicitly posthoc development view of the original71 raw sessions.
G03 completed-body coverage failures and its rejected fit remain unchanged.
No raw session is replaced. Sealed B2 data remains unavailable during development.

The observation is one complete five-byte outerTLS23 header: its declared length
and the time those header bytes became contiguous and available. This includes
encrypted handshake records. It does not require body completion and does not
claim that the declared bytes arrived or that a TLS session completed.

The base detector combines15 window rules,6 whole-flow features and2 capture-order
count signatures. Engineer-authored conjunctions may then be added one actual
adaptive experiment at a time. Every rule, window, reconnect and actual flow uses
one jointly calibrated group/direct-flow FP budget. Incomplete observations use
the conservative [R4 analysis](../../dpi-g03/ANALYSIS-R4.md).

The consumer independently checks header counts, selected metadata, physical TCP
inventory, close evidence and PRIMARY versus whole-capture flags. Existing flows
may have their first header before the primary interval and remain active inside
it. Known empty header observations abstain and retain their flow denominator.

The captured Chrome startup context can precede the declared80-second barrier;
its bootstrap prefixes remain diagnostic in this initial policy. Native startup
occurs after that barrier. Results therefore describe this observation schedule,
not all possible censor exposure to every new connection. This limitation must
remain visible in development and held-out reports.

The extractor uses seekable PCAP and two-pass earliest metadata selection.
Although a TLS header is available causally, this full policy is **shadow scoring**,
not an implemented online censor or proof of bypassing a real ISP.

```sh
node lab/dpi-g04/ensemble/build.cjs
./ensemble catalog -engine PINNED_CLASSICAL -ordering-sha ORDER_SHA -coverage-sha COVERAGE_SHA -out catalog.json
./ensemble fit -index INDEX -freeze PROJECTION -engine PINNED_CLASSICAL -out NEW_POLICY
./ensemble evaluate -index INDEX -freeze PROJECTION -engine PINNED_CLASSICAL -policy POLICY -out REPORT
```

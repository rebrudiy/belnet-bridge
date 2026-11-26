# Bounded PCAP windows

```sh
go build -o out/dpi-g01/tooling/observer ./lab/dpi-g01/observer
out/dpi-g01/tooling/observer -pcap CAPTURE.pcap -meta GROUP.json -out WINDOWS.json
```

Metadata example: `out/dpi-g01/tooling/EXAMPLE-observer-meta.json`. The runner must
finish capture, collect its drop count and actual UTC bounds, then extract. Use
classic PCAP with full packets; Ethernet/VLAN, IPv4/IPv6, raw IP and Linux
SLL/SLL2 are supported. PCAPng and IP-fragment reassembly are not supported;
unsupported/truncated/dropped data cannot become a complete observation.

One PCAP covers the whole group, both entry connections and reconnects. All
classes use this parser and its PCAP TCP-record completion clock. Group windows
are 0–2/8–10/18–20/28–30 s from the group's first complete outer TLS23 record.
Each new flow also gets its own first 2 s window. Duplicate prefix/fixed windows
are explicit; a group OR does not count them as independent trials.

`measured_seconds` is 45 from capture start. A flow first seen after that measured
scope is `not_applicable`. Predeclare a 47 s capture if needed: two seconds of grace
finish prefixes started before 45 s without introducing new grace-period windows.
Without grace, a prefix extending past capture end is explicitly incomplete.

At most 64 events are selected per feature window, while the parser continues
counting and processing the entire capture. Selection truncation is not capture
censoring. A 30,000-record fixture verifies late windows beyond the old 2048 cap.

Bounds: 512 flow instances, 256 pending segments/stream, 256 KiB pending bytes/stream,
8 MiB pending bytes globally, 1 MiB per captured packet, 256 MiB input group cap.
Record bodies are skipped incrementally. No complete TLS payload is retained for
in-order traffic. Out-of-order bytes are bounded and never exported. Different
SID/TLS reconnects remain separate TCP flows; this parser cannot infer nativeSID.

Outputs include absolute window bounds, 5tuple, group/split/profile, record counts,
coverage reasons, selected length/direction/time events and whole-file SHA256.
Statuses distinguish `complete`, `sparse`, `not_applicable`, `missing_syn`,
`malformed`, `byte_censored`, `count_censored` and `incomplete`. Sparse means the
capture covered the interval; it does not mean enough records exist for a rule.
Any capture drop/cap, unresolved TCP gap or missing prefix remains visible.
Credentials, TLS/application payload and native packet contents are not exported.
UDP/nonce activity must be joined externally using the absolute UTC intervals.

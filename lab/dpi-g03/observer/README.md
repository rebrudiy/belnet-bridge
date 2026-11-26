# G03 bounded PCAP observer

```sh
go build -o out/dpi-g03/tooling-observer/observer ./lab/dpi-g03/observer
out/dpi-g03/tooling-observer/observer -pcap GROUP.pcap -meta GROUP.json -out WINDOWS.json
```

G03 is a new schema/version. G01 source, binaries and strict historical results
remain unchanged. No model fitting or traffic acquisition occurs here.

## Frozen B measurement contract

Use a **prelaunch Linux-VM UTC** `measurement_start_unix_micros`, before the first
outer TLS record, for **both** classes. The common primary horizon is80s:
35s startup/ordinary-start plus45s workload. Initial native bootstrap and every
new/reconnected flow inside80s are PRIMARY. There must be no bootstrap prefix
before measurement in the planned B capture; do not move the measurement start
after a difficult initial handshake.

Example metadata is `out/dpi-g03/tooling-observer/EXAMPLE-B-meta.json`:

```json
{
  "measurement_start_unix_micros": 1795132800000000,
  "measured_seconds": 80,
  "window_offsets_seconds": [0,8,16,24,32,40,48,56,64,72,78],
  "prefix_grace_seconds": 2
}
```

Each fixed window is2s, with `window_kind="phase_fixed"`. Every flow's first
complete TLS23 creates its own2s `flow-prefix`. Prefixes started before80s can
finish during the declared2s grace; flows first observed during grace create no
new primary obligations. Actual capture must cover the required interval:
declaring grace does not supply missing packets. Preserve full warmup/SYN
context; clipping a PCAP to workload start loses evidence.

`measured_seconds` is bounded2..90, default45. Custom fixed offsets are strictly
increasing nonnegative integer seconds; every2s window must fit the primary
horizon. Maximum45 fixed windows,64 selected records/window. Defaults remain
0/8/18/28 for a45s development horizon. Without an explicit measurement start,
legacy `group-fixed` windows use the true minimum complete TLS23 UTC; a bounded
seekable two-pass PCAP scan discovers that anchor. No packet sorting or spooling
occurs. Use explicit prelaunch start for B.

A flow first recorded **before** an explicitly declared start gets a
`bootstrap-prefix`: diagnostic `primary=false`, never in `observations`.
This supports separately declared development scopes; it must not silently
exclude B's initial transport establishment. `diagnostic_observations` retains
these windows even when ineligible. `windows` contains every declared window;
`observations` contains only coverage-eligible primary windows.

## Clock and TCP semantics

The input file order is preserved. A timestamp reversal **between different TCP
flow instances** is counted/reported as capture-order skew, without globally
invalidating unrelated flows. Counts, maximum negative span and first32 samples
are exported in `clock_diagnostics`. These diagnostics do not prove a bound on
clock error or distinguish every possible clock jump from scheduling skew.

A reversal within a bidirectional flow, directional stream, or completed-record
sequence invalidates that flow's windows. Affected group coverage remains
invalid. Metadata bounds, missing SYN/SYNACK, malformed records, unresolved gaps,
overlap conflicts and capture drops/caps remain explicit coverage failures.

Pending TCP segments retain their own arrival timestamps. Record completion is
the maximum timestamp of the consumed header/body constituents and their
contiguous-stream availability (including the packet closing a sequence gap).
A record cannot complete before a stored constituent or its required gap fill.
The minimum of **all** completed TLS23 timestamps is exported separately as
`group_first_tls23_utc`; it does not replace an explicit measurement start.
Events use this completion clock for both classes; `at_micros` is relative to its
window start, truncated to microseconds. PCAP timestamp resolution is exported.

TLS type23 includes encrypted handshake records. Length/direction/time do not
identify plaintext, dummy content, native success, or a useful DPI discriminator.
Join VM UTC windows externally to current-SID native UDP and nonce proof metadata.
Capture lifecycle metadata must itself be VM UTC or explicitly conservative VM
bounds; host `Date` timestamps are not silently converted.

## Bounded processing and validation

Classic PCAP, Ethernet/VLAN, IPv4/IPv6, raw IP, Linux SLL/SLL2 are supported.
PCAPng and IP-fragment reassembly are unsupported. Limits remain512 flow
instances,256 pending segments/stream,256KiB pending bytes/stream,8MiB globally,
1MiB captured packet and256MiB PCAP. Bodies are skipped incrementally. Every
record is counted, while only the first64/window become features; there is no
2048-record capture cutoff. Different windows/reconnects are correlated, not
independent trials. Coverage eligibility is separate from a rule's evidence
eligibility. Sparse means the interval was covered, not that a detector can act.

```sh
go test -race ./lab/dpi-g03/observer
go vet ./lab/dpi-g03/observer
```

Regressions include a16µs cross-flow reorder with a true-minimum anchor,
per-flow causal rejection, pending-before-gap availability, maximum constituent
time, initial/bootstrap inclusion in an80s prelaunch horizon,45s development
scope, declared vs missing grace,30,000-record late-window survival, malformed
input, overlap conflicts and memory/count caps. Payloads and tokens are never
exported. Versioned binaries and source hashes are in the tooling manifest.

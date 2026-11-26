# G02 / A2 runtime

Finite development checkpoint, not DPI collection or a new final test.
G01 remains immutable. See [PROTOCOL](../PROTOCOL.md).

Four fresh framed deployments: retain0 / expiry100ms / expiry100ms / retain0.
`G02_MAX_QUEUE_AGE` reaches only the client flag. Server/downlink, wire, SID/token
and native crypto are unchanged. Expiry drops stale input at write-start; it
is not an end-to-end100ms delivery promise. All input/drop/blocked-write history stays.

## Offline preparation and lead-owned run

```sh
node lab/dpi-g02/runtime/prepare.cjs --directory lab/dpi-g02/run/prepared-a
node --test lab/dpi-g02/runtime/runtime.test.cjs
go test -race ./lab/dpi-g02/runtime/cmd/probe
go vet ./lab/dpi-g02/runtime/cmd/probe
```

Preparation uses ephemeral Docker `--network none` for keys/config checks and
local compilation. No listeners/native traffic start. Private assets and descriptor
remain in ignored `run/`. Build evidence has `command:[...]` and
`log:{path:"/absolute/build.log",sha256:"actual hash"}`.

```sh
node lab/dpi-g02/runtime/freeze.cjs \
  --adapter lab/dpi-g02/bin/belnet-bridge-a2-v1 \
  --prepared lab/dpi-g02/run/prepared-a/preparation.json \
  --build-evidence /absolute/build-evidence.json --run-id a2-20261119
node lab/dpi-g02/runtime/stage-a.cjs \
  --freeze lab/dpi-g02/run/freeze-a2.json --validate-only true
```

Only the lead launches, after review, by omitting `--validate-only`.
Actual binary/config/source/build hashes and embedded finite plan must match.
No existing Go443 baseline is used. Native entries/relays/service stay unchanged;
only `bb-g02-*` containers are owned. Active G01 causes refusal, never cleanup.
After four deployments the run stops. B remains closed.

## Clocks and evidence

Warmup starts5/15/25s (timeout8s); phase45s requests start
0/3/12/17/22/27/32/37s (timeout5s), alternating4096/16384 bytes.
At10s client core stops for2s; Go/native/SID remain alive. Every deployment has
fresh native data. Failed last warmup makes app comparison inconclusive.

`probe clock` emits VM UTC/unix_micros. Phase, proof, packet and interruption
comparisons use that same Linux VM clock. Before/after VM samples bracket both
stop and start. Strict post uses after-start; overlaps remain straddling.
Host monotonic time only schedules. VM-minus-host offset bounds and uncertainty
are retained, including host millisecond resolution; no host timestamp is used
to classify packet freshness. Nonces carry started/finished Unixµs.

The own `.bdx`:8082 helper writes UTC/Unixµs nonce/size in `service.log`.
Full snapshots retain packet_events, udp_inputs and expired_events. Compact1s
snapshots omit these arrays while retaining counters/truncation flags. Queue-drop
counters are cumulative per SID: do not sum them over reconnect records.

PCAP covers warmup plus full45s; explicit VM phase boundaries define cost windows,
not first TLS. Capture is bounded256MiB, waits for the listening banner and marks
caps/drops/forced cleanup incomplete. Plaintext21990 is excluded. Shared entry UDP
taps need SID/tuple correlation to avoid attributing older retained-session packets.
Raw attempts remain under `lab/dpi-g02/run/stage-a2-ID/`; no reroll to success.

Received/captured counters do not prove saved-PCAP completeness. Received-vs-written
accounting remains explicitly unknown until passive reconciliation, never an automatic rerun.

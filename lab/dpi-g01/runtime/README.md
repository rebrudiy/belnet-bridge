# G01 Stage A runtime

This directory prepares and runs only the finite engineering checkpoint in
[PROTOCOL](../PROTOCOL.md). No DPI collection starts automatically after it.
Native deployments are fresh, ordered v2 / framed / framed / v2. All carry the
API-compatible `train` label: this is development, not a new statistical test.

## Offline preparation and freeze

```sh
node lab/dpi-g01/runtime/prepare.cjs --directory lab/dpi-g01/run/prepared-a
node --test lab/dpi-g01/runtime/runtime.test.cjs
go vet ./lab/dpi-g01/runtime/cmd/probe
```

Preparation uses Docker `--network none` for key generation and sing-box syntax
checks. It compiles the bounded nonce helper; it does not start a core, native
client, decoy listener or network experiment. Credentials/certs stay in ignored
`run/prepared-a/private/`; only hashes and validation results appear in the descriptor.

The lead supplies two evidence files:

```json
{"command":["env","GOOS=linux","GOARCH=arm64","CGO_ENABLED=0","go","build","..."],
 "log":{"path":"/absolute/build.log","sha256":"actual log SHA256"}}
```

```json
[{"entry":"entry1","enforce":false,"live_binary_sha256":"actual /proc/PID/exe SHA256"},
 {"entry":"entry2","enforce":false,"live_binary_sha256":"actual /proc/PID/exe SHA256"}]
```

Then freeze the actual adapter ELF, build log, complete runtime/adapter sources,
protocol, finite plan, configs, token, certs, helper, native image/binary and sing-box:

```sh
node lab/dpi-g01/runtime/freeze.cjs \
  --adapter lab/dpi-g01/bin/belnet-bridge \
  --prepared lab/dpi-g01/run/prepared-a/preparation.json \
  --build-evidence /absolute/build-evidence.json \
  --baseline-evidence /absolute/baseline-evidence.json \
  --run-id a20261119
node lab/dpi-g01/runtime/stage-a.cjs \
  --freeze out/dpi-g01/runtime-preparation/freeze-a.json --validate-only true
```

Freeze refuses missing/mismatched hashes and overwriting an existing manifest.
`common.sourceHashes()` excludes the lead's unused `review-stage-a.cjs` and test
files. `adapterSourceHashes()` includes production root Go, internal non-test
assets, go.mod and go.sum. No secrets are printed. Do not rebuild after freezing.

## Explicit acquisition command for the lead

```sh
node lab/dpi-g01/runtime/stage-a.cjs \
  --freeze out/dpi-g01/runtime-preparation/freeze-a.json
```

Without a valid freeze this exits before any Docker mutation. It refuses an old
running `bb-dpi-v2-client`, existing `bb-g01-*` containers and existing run data.
It never stops the old client itself or rewrites existing entry443 policy.
Only its own `bb-g01-*` processes are created and removed. Native entries, relays,
service and old8081 remain unchanged. A dedicated service helper on8082 logs JSON
UTC/unix-microsecond nonce evidence to `run/.../service.log`.

Candidate cores use19444/18444, Go servers loopback21990, client TCP19091/19092.
The server allow rule requires TCP to literal127.0.0.1:21990; UDP and other requested
addresses/ports are rejected. uTLS Chrome and REALITY public-key pinning are used.
Full sing-box directory is mounted read-only to include its libcronet dependency.

## Schedule and retained evidence

Warmup always has three starts5/15/25s, timeout8s. Phase45s has nonce starts
0/3/12/17/22/27/32/37s, timeout5s, sizes4096/16384 alternating. At10s candidate
client core stops for2s. Baseline uses only private-client TCP443 DROP plus WSS
rotation for the same outage. Native and Go adapter processes stay alive.

Only proofs whose **actual client start** is after interruption end count toward
recovery. Straddling proofs are retained separately. Gate ≤10s is observational;
failed last warmup or last v2 baseline makes the comparative app result inconclusive.
No timeout/failure is rerolled or called DPI evasion.

Capture waits for tcpdump's actual `listening on` banner before native starts.
It includes warmup and the full45s phase; explicit phase UTC boundaries, not the
first TLS record, define cost windows. Host sink never overwrites old bytes and
stops at256MiB. Cap/drop/missing counters/forced cleanup mark incomplete. Cleanup
has finite stop/kill/close bounds. PCAP itself can end with a partial record at cap.

Per-group `result.json`, `proofs.jsonl`, full boundary `snapshots.jsonl`, compact
1s `counters.jsonl`, raw UDP metadata taps, PIDs, firewall rules and all logs remain
in ignored `lab/dpi-g01/run/stage-a-ID/`. Compact snapshots omit packet_events and
udp_inputs. Metadata truncation flags remain. Queue drop counters are cumulative
per peer/SID: do not sum them repeatedly across reconnect connection records.
Shared-namespace UDP taps can include older retained sessions; correlate source
port inventories and session hashes before attributing traffic to a deployment.

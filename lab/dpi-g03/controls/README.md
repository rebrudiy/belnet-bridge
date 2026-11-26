# G03 controls — offline preparation

These helpers prepare the next comparison. **No B dataset, browser session, public-site run, native deployment or packet capture has been collected with them.** Short localhost/net.Pipe unit fixtures are software checks only. Cohorts, assignments, seeds, freeze, capture limits and A2 go/no-go still belong to the lead's protocol.

## One observer

```text
HOST fresh Chrome ── host127.0.0.1:19880 ─┐
                                         │ CONNECT proxy in Docker
native sing-box VLESS TCP ─ HTTP detour ───┘        │
                                        [egress PCAP + VM clock]
                                                  │ TCP443
                public origin OR entry1/2 REALITY443
                                         ├ native authenticated transport → existing C++ UDP1090
                                         └ ordinary TLS/WSS fallback → bench-server18444
native inner app → ws://<service>.bdx/ws → same benchmark engine
```

Publish the proxy **only** as `127.0.0.1:19880:8080`. A private Docker network address is used by the native core's HTTP detour. Do not publish an open CONNECT proxy. Capture upstream traffic, excluding Chrome→proxy8080. Public and matched private targets use443. A Docker proxy with public/private NICs may require `tcpdump -i any`; the extractor must then support Linux SLL/SLL2. This document does not deploy that topology.

Both classes must actually traverse this proxy. A second capture beside a direct native path does not satisfy the design. Proxy events provide `upstream_local` and `upstream_remote` to join each tunnel with PCAP by tuple and VM timestamps. Group IDs exist only in proxy metadata.

This is an **explicit TCP-only subset**: Chrome planner sets `--disable-quic`; CONNECT forwards TCP, not UDP/HTTP3. NetLog/CDP confirms browser activity/playback, never supplies DPI timings. Equal observer clock does not remove TLS implementation, certificate size, origin or RTT differences; matched private controls and per-stack/origin results remain necessary.

## Programs and API

Build from this directory, with `GOWORK=off`. Dependencies are isolated from root production.

| Program | Explicit inputs | Output / role |
| --- | --- | --- |
| `cmd/connect-proxy` | `-listen 0.0.0.0:8080 -config <private frozen JSON>` | JSONL tunnel VM times, actual upstream tuples, encrypted byte counts, accept/error status |
| `cmd/bench-cert` | `-directory <new private directory> -hosts decoy.test` | Fresh24h lab cert/key and public SPKI SHA256; refuses overwrite; never changes OS trust |
| `cmd/bench-server` | `-listen 127.0.0.1:18444 -cert <pem> -key <pem>` | Ordinary TLS/WSS backend, JSONL actual workload events |
| `cmd/bench-server` native service | `-listen :8083 -native-plain -role native-application` | Same HTTP/WebSocket engine for the existing `.bdx` service; deployment owned by lead |
| `cmd/bench-client` ordinary | `-mode ordinary -url wss://decoy.test/ws -proxy http://<proxy>:8080 -spki <lab SPKI> -family rpc -seed <decimal> -duration 45s` | Finite Go WSS control; public endpoints omit SPKI and keep normal TLS verification |
| `cmd/bench-client` native | `-mode native -url ws://<service>.bdx/ws -dns 127.3.2.1:53 -family rpc -seed <decimal> -duration 45s` | Inner actual native application; requires `.bdx`, loopback native DNS, no direct proxy bypass |

Commands above describe API and **must not be run as B acquisition until freeze**. No default workload endpoint/seed is silently chosen. `-nonce` is optional only because a fresh random64hex nonce is generated; freezing assignment/nonce is the collector's responsibility.

`examples/proxy.json` is a proposed allowlist, not a record of public origins successfully accessed. Public DNS resolves IPv4, rejects private/special addresses and dials the checked literal IP. Explicit `.test`/entry-address mappings can target only entry1/2 IPv4 addresses. They cannot remap `www.google.com` to a lab certificate. Denials/timeouts remain failures; expanding the allowlist requires a new frozen config, not hidden retry-until-success.

`examples/native-detour.json` is a **fragment**: preserve frozen UUID/REALITY keys/uTLS and set VLESS `detour` to the HTTP CONNECT outbound. HTTP CONNECT and dial-detour are documented by [sing-box HTTP outbound](https://sing-box.sagernet.org/configuration/outbound/http/) and [dial fields](https://sing-box.sagernet.org/configuration/shared/dial/). Pinned1.14.4 option types confirm [VLESS embeds DialerOptions](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/vless.go) and [Detour exists](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/outbound.go). Newer1.15-only HTTP-version options are intentionally omitted. **This detour has not been functionally exercised here.**

`browser-flags.cjs` exports pure `chromeArgs({profile,artifactRoot,proxy,labSPKI})` and `workloadURL(endpoint,{family,seed,nonce,durationMS})`. It never launches Chrome or creates a profile. Profile must be fresh under the run directory. Only exact lab SPKI exceptions are allowed; public TLS stays verified, no generic ignore-certificate flag or trust-store modification. The collector supplies the installed Chrome path/version, starts its own isolated profile and closes it afterward. No user profile, login or CAPTCHA bypass.

## Shared six-family engine

`/bench`, `/plan`, `/ws`, `/download` accept only `family`, fixed16lowerhex `seed`, integer `duration_ms`1000..80000 and fixed64lowerhex `nonce`. No group/class/split/corpus IDs are accepted on wire. Same source workload and paired variants must share a split; identifiers remain in collector metadata. `/upload` is a bounded HTTP POST digest fixture. HTTP convenience endpoints are auxiliary; complete nonce/count/duration event logging is implemented for **WebSocket workloads**.

| Family | Independent behavior |
| --- | --- |
| download | Server binary4–32KiB chunks,70–260ms cadence |
| upload | Client4–16KiB chunks,40–160ms; independent periodic server accepted-byte/SHA256 ACKs |
| rpc | Client JSON requests; actual validated requests trigger delayed computed responses, never echo |
| push | Server JSON messages with independent timing/sizes |
| chat | Both directions have distinct generated messages and independent cadence |
| idle | Open finite connection, no dummy application actions |

Bounds:80s maximum workload (main workload45s; long-flow controls80s),4MiB application bytes per direction,32KiB frame,16 simultaneous backend requests; CONNECT maximum64 tunnels and180s hard lifetime. Backpressure/network failures can change actual schedule; expected plan is not evidence of actual transfer. Logger records actual counts/nonce/start/finish/error/duration; Go clients report RPC validation, received download-pattern checks/SHA256, upload ACK prefix digests and early closure. An ACK verifies only its accepted prefix; `upload_verified_all_sent` says whether all sent bytes were acknowledged. Browser counters explicitly report download/upload integrity as unverified; no digest claim is inferred from byte counts. Browser page exposes `window.__bench` counters and RPC checks. Synthetic benchmark traffic must never be labelled as real Google/YouTube traffic.

`bench.NewPlan`, `bench.WorkloadURL`, `bench.RunClient`, `bench.NewHandler` are the shared Go APIs. Handlers/proxy expose bounded `Shutdown(ctx)` that cancels and joins active work, including hijacked WebSockets and event logging. Caller owns HTTP server shutdown/deadlines and log durability. No scheduling/background goroutines survive a successful shutdown.

## Collector obligations

See `collector-contract.json`. Store source/ELF/core/config/allowlist/certificate-SPKI hashes before acquisition. Record actual clock/capture readiness/cap/drop reconciliation; missing or truncated windows are ineligible/unknown, never evasion. Whole deployment/session and paired workload variants share split. Primary ordinary HTTPS/WSS and actual native BelNet are distinct from diagnostic authenticated REALITY carrying another payload.

Use explicit **PRELAUNCH VM** `measurement_start_unix_micros` before first outer connect for BOTH labels: primary80s, capture82s including2s grace. Two-second sampled windows start at0/8/16/24/32/40/48/56/64/72/78s, plus first2s of every new TCP/TLS flow/reconnect inside80s. **Initial native bootstrap is PRIMARY.** A35s prelude followed by45s common main workload does not remove the prelude from observation. Long-flow ordinary controls use the same API with `-duration 80s` or `duration_ms=80000`, so the connection actually persists through80s. Only genuinely premeasurement flows are diagnostic (planned B should have none). Grace finishes already obligated prefixes, not new grace-start flows. Do not substitute host lifecycle UTC for VM time. Group-level OR across windows/reconnects needs aggregate calibration.

Actual public controls require public activity evidence: Google status/query and video media bytes plus increasing playback `currentTime`; preserve access failures separately. No login, CAPTCHA bypass or simulated page replaces unavailable YouTube. Old14 proofs/development controls are not fresh B test data. Native-positive windows need actual native UDP plus correlated `.bdx` nonce/workload evidence, not merely a listening REALITY socket.

## Verification

`GOWORK=off GOPROXY=off go test -race ./...`, `go vet ./...`, and `node --test browser-flags.test.cjs` cover deterministic bounded plans, real RPC vs echo, digest, wire identifier lengths, lab/public pin isolation, public-address policy, literal IPv4 dial, buffered CONNECT data/byte counts, cancellation/shutdown and fresh-profile launch planning. These checks do not establish DPI evasion or native detour viability.

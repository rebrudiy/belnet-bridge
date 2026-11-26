# Private native BelNet proof

Six real BelNet relays, one client and one `.bdx` HTTP service. Native paths are configured for three hops; some reuse a relay identity in this small topology. Captures do not attribute individual requests to specific paths. HTTPS/WebSocket terminates inside the first relay's container and delivers only to that relay's own IWP socket. There is no separate forwarding host or general IP tunnel.

Requires Docker, Go, OpenSSL and ripgrep. From the repository root:

```sh
GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o docker/belnet-bridge .
docker build --platform linux/amd64 -t belnet-bridge:native -f docker/Dockerfile .
./lab/run.sh control
./lab/run.sh dpi
./lab/run.sh dpi-tunnel
```

| Mode | Client network | Expected result |
|---|---|---|
| control | Native UDP to entry1/entry2 only | `.bdx` HTTP succeeds |
| filter | All UDP leaving client is dropped | HTTP fails; UDP policy test |
| tunnel | First-hop datagrams enter verified TLS to the same entry relays; direct UDP is dropped | HTTP succeeds |
| dpi | NFQUEUE rejects IWP Intro packets verified against six public router identities; other traffic is accepted | Native BelNet fails; benign UDP and HTTPS pass |
| dpi-tunnel | Same classifier, same-node TLS transport, no blanket UDP block | HTTP succeeds; benign UDP and HTTPS pass |

The classifier checks the 224-byte initial IWP packet's keyed BLAKE2b tag. Its decision does not depend on an IP address or port. Native local proxy packets after DNAT are excluded from the wire classifier. Firewall rules still restrict direct first-hop sessions to the two entry relays.

This is an isolated private network running the official v0.9.8 binary. It does not prove mainnet integration, real national-censor resistance, or statistical indistinguishability from browser HTTPS. The queue and packet capture utilities share existing node namespaces and forward no traffic.

Artifacts contain warmup failures, ten steady HTTP requests, matching random nonces in service logs, native paths, session/path failures, firewall counters and eight packet captures. DPI runs also record classifier decisions, benign positive controls, public identities and binary SHA-256 hashes. `summary.json` separates established session timeouts from pending connection timeouts.

The TLS-only claim applies to BelNet transport; the deliberate benign UDP echo probe appears separately on the wire. Event counts cover all eight saved node logs. Median latency uses the mean of the middle two values for even sample counts.

Tunnel mode stops both HTTPS listeners for 30 seconds and measures recovery. Recovery can fail even after WebSocket reconnects: the native entry relay can retain an old client session for five minutes. Consult the recorded result. `BB_RECOVERY=0` skips this repeat experiment; its default is enabled.

The classifier stops after measurement while its queue remains fail-closed. Later WebSocket errors are teardown effects. The final result records measurement end from the classifier summary and preserves separately collected transport tails.

Private keys and raw artifacts live in ignored `lab/run/` and `lab/results/`. Publish neither keys nor bridge tokens. Old directories marked `diagnostic` are excluded from final claims. The diagnostic `probe tick` is never invoked by the runner.

The native utility image follows Docker host architecture, allowing official amd64 BelNet to run under emulation on ARM. The client alone enables local routing settings for transparent UDP interception. First-hop restrictions use firewall rules because native `strict-connect` also removes intermediate relay contacts in this release.

Overrides: `BB_IMAGE`, `BB_PLATFORM`, `BB_CAPTURE_IMAGE`, `BB_ATTEMPTS`, `BB_SAMPLES`, `BB_RECOVERY`. The private network has no external route. Stop this lab with `docker-compose -f lab/compose.yml down`; utility containers are named `bb-lab-capture-*` and `bb-lab-censor`.

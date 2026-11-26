# Mature transport baseline

**VLESS + REALITY + Vision + XUDP works for ordinary-size UDP on the same first
node. The stock sing-box UDP adapter does not meet our full datagram and reconnect
contract.** Tested version: official sing-box 1.14.4 Linux arm64, archive SHA256
`436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26`.

```text
BelNet client UDP → local sing-box → TCP/REALITY → sing-box on FIRST BelNet node
                                               → 127.0.0.1:1090 on that node
```

No extra VPS. The first node runs two processes. In the private smoke test, a UDP
echo service replaces BelNet 1090 and a local self-signed TLS 1.3 server replaces
the REALITY decoy. This proves transport functionality, not real BelNet traffic,
credible public HTTPS camouflage or DPI evasion.

| Check | Observed result |
|---|---|
| 1 / 128 / 1200 byte datagrams | Exact round trip; steady local RTT ≈0.2–0.3 ms |
| Empty UDP datagram | Timeout, not delivered |
| 60,000 / 65,507 bytes | Truncated to ≈16.1 KiB; failed exact comparison |
| Client restart, same client source 21900 | Recovers; server UDP source port changes |
| Authorized client requests 192.0.2.123:5555 | Server forces delivery to local 1090 |
| Wrong UUID / REALITY shortID / server public key | No UDP delivery |

Numbers are one private-host lab measurement. See `out/dpi-v2/mature/result.json`,
`echo.jsonl`, endpoint logs and `runs/` for preserved attempts. `transport.pcap`
covers the initial functional sequence, including the failed empty-datagram flow.

## Reproduce

Requires Docker, Go, Python3, curl and shasum; existing lab capture image
`belnet-bridge:evolution-refactored` is optional for pcap. No published ports.

```sh
lab/dpi-v2/mature/fetch.sh
python3 lab/dpi-v2/mature/smoke.py
```

The runner creates its own internal Docker network and containers, then removes
only those it created. Configs contain freshly generated lab-only credentials.
Files: `make-configs.py` generates validated JSON; `probe.go` compares payloads and
logs native UDP socket identities; `smoke.py` runs controls and archives results.

## Integration decision

For a BelNet test, run the server config in the first node's network namespace
with its actual listener at 127.0.0.1:1090. Replace the lab decoy address/name with
an appropriate TLS endpoint and provision public key, shortID and per-user UUID
to the client. Point the BelNet client bootstrap/first-node endpoint at the local
UDP listener 19090; the first node's advertised cryptographic identity must still
match. Root's native harness must supply that BelNet configuration and record
actual session disconnects. Echo success alone does not establish this.

Keep the server's UDP-only routing rule with destination override and final
reject. The client cannot choose an arbitrary Internet egress destination through
this config. The REALITY fallback still connects to its configured decoy.

The client pins the REALITY public key; no `insecure` flag is used. UUID is client
authorization. The server holds the private key. Leaked UUID/shortID requires
credential rotation; an exposed address remains blockable by IP. The first node
still sees the client's source IP. TCP loss causes head-of-line blocking for UDP.

A thin bounded adapter is needed if empty/large datagrams or native UDP socket
identity across reconnects are requirements. It should preserve an authenticated
session's local UDP socket on the same first node. Reuse REALITY for masking;
do not infer reconnect identity from the external source IP alone.

## Upstream and packaging

- [Direct inbound](https://sing-box.sagernet.org/configuration/inbound/direct/)
  supplies a local UDP listener and static destination.
- [VLESS outbound](https://sing-box.sagernet.org/configuration/outbound/vless/)
  documents XUDP. [Pinned source](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/vless/outbound.go)
  shows the outer TCP/TLS dial. SagerNet's separate UoT protocol is not XUDP.
- [TLS/REALITY fields](https://sing-box.sagernet.org/configuration/shared/tls/)
  define key pinning, shortID and decoy handshake configuration.
- [Routing actions](https://sing-box.sagernet.org/configuration/route/rule_action/)
  define destination override and rejection.
- [sing-box license](https://github.com/SagerNet/sing-box/blob/v1.14.4/LICENSE):
  GPL3-or-later plus a name/association condition. Preserve attribution and plan
  corresponding-source distribution. Prefer a separately managed executable;
  linking into BelNet needs a license compatibility review. Official binary is
  ≈72 MiB plus bundled libcronet; a minimal feature build needs separate validation.
- [Xray-core license](https://github.com/XTLS/Xray-core/blob/main/LICENSE): MPL2.
  Xray is a packaging alternative; it was not built or measured in this baseline.

Pin versions, retain checksums, track upstream fixes and define who owns updates,
credential provisioning and mobile/desktop packaging with BelNet maintainers.

# Native first-node transport

19 November 2026. Implemented and exercised with real private BelNet v0.9.8. [Proof](PROOF.md). No mainnet/ISP claim; full process restart recovery remains unresolved.

```text
BelNet client → local UDP redirection → udp-client
              → WSS → udp-server + first BelNet node → BelNet route
```

The transport receiver and BelNet run on the same first node. This is not a generic system proxy or an extra forwarding host.

## Start

Set the same `BRIDGE_TOKEN` in both process environments. `-token` is an alternative; do not put real secrets in shared examples.

On the first node:

```sh
belnet-bridge udp-server -listen :443 \
  -target SAME_NODE_IP:1090 -cert entry.pem -key entry-key.pem
```

Use that node's actual IWP listener. The operator fixes the destination; clients cannot select arbitrary targets. Same-node placement is a deployment requirement, not enforced by parsing the target. Existing BelNet may reject loopback binding.

On the client:

```sh
belnet-bridge udp-client -listen 127.0.0.1:2090 \
  -url wss://entry.example/ws -ca lab-ca.pem -profile profiles/baseline.json
```

The certificate must match the hostname. `-ca` adds trust for this client process alongside system roots; omit for a normally trusted certificate. WSS/TLS 1.3 is mandatory; redirects are refused.

## Required routing

BelNet sends to RouterContact peer addresses, not automatically to localhost. OS redirection or a transport hook must map selected peers to the adapter and preserve identity/return addressing; the entry HTTPS connection must bypass that redirection.

The [private lab](../lab/README.md) supplies seeded peers and firewall-based first-hop restrictions. Stock `strict-connect` requires at least two nodes and also filters intermediate contacts in this release. Public bootstrap/admission remain open. Three configured hops can repeat a relay in this small topology.

## Session continuity and shaping

`-profile FILE` enables v2 without experimental control endpoints. Profiles define separate upload/download padding, batching, pacing and dummy policies; zero values add no intentional shaping. Strict JSON parsing rejects unknown fields. The client generates an authenticated random session identifier; the server retains its UDP socket across WSS reconnects. Retention is bounded to 64 sessions, with opportunistic cleanup after six inactive minutes. Reuse depends on both processes remaining alive. Active WSS connections are also capped at 64. The fixed UDP target is never supplied by the client.

The [15-round experiment](EVOLUTION.md) exercised actual policy changes but did not reduce detection. `profiles/baseline.json` is the minimal v2 example; the frozen experimental policy is evidence, not a recommended camouflage setting.

## Limits

64 local peers, 64 queued datagrams per peer, 64 server sessions; overload can drop packets. Per-session local UDP ports isolate peers, but their common source IP can aggregate upstream limits. Native logs include events/errors. Legacy TUN/NAT modes remain separate.

The final DPI+HTTPS run achieved 10/10 steady requests, median 59.5 ms. After both listeners stopped for 30 seconds, WSS reconnected but HTTP recovery was 0/8. That historical run used the earlier transport. V2 now retains UDP associations during WSS rotation; full process restart recovery still needs work. Blanket UDP filtering is a policy test; the [actual IWP detector](../internal/iwpdetector/README.md) and benign probes are documented separately.

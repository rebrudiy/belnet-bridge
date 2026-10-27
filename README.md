# belnet-bridge

Stealth bridges for [BelNet](https://github.com/Beldex-Coin/belnet): carry BelNet's traffic inside an ordinary HTTPS/WebSocket connection so that DPI which fingerprints and throttles LLARP sees only TLS to a normal-looking website.

Motivation: [Beldex-Coin/belnet#34](https://github.com/Beldex-Coin/belnet/issues/34) — ISPs detect LLARP and throttle or block it, and running BelNet on top of a commercial VPN causes routing loops. Censors increasingly block VPN protocols by fingerprint; only traffic that looks like something else survives.

## How it works

```
 censored network                                         open internet
┌──────────────────────────────┐                 ┌──────────────────────────────┐
│ belnet ──UDP──► TUN bb0      │                 │                              │
│                  │           │  TLS :443       │  belnet-bridge server        │
│ belnet-bridge client ════════╪═════════════════╪═► TUN bb0 ─NAT─► BelNet     │
│  (IP packets in WebSocket)   │ looks like HTTPS│                    routers   │
└──────────────────────────────┘                 └──────────────────────────────┘
```

- **Layer-3 tunnel, not a single proxy.** BelNet talks UDP to many routers at once, so the client routes *all* of BelNet's packets through a TUN interface; one WebSocket message = one IP packet.
- **Camouflage.** The server is a plain website. Only a request to the secret path with the right bearer token is upgraded; everything else (probes, scanners, wrong token) gets a default "It works!" page — the same idea as Tor's WebTunnel bridges. It can also run behind a real web server or CDN (`-cert` empty = plain HTTP behind a TLS proxy).
- **Per-client addresses, anti-spoofing.** Each client gets its own tunnel IP; packets with any other source address are dropped.
- **No new trust in Beldex.** The bridge only sees encrypted LLARP packets, same as the ISP would.

## Demo (Docker)

The compose setup simulates censorship: the client's `eth0` drops **everything** except TCP to the bridge on port 443. BelNet then bootstraps and connects only through the bridge.

```
GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o docker/belnet-bridge .
docker compose -f docker/compose.yml up --build
```

Check what the "ISP" sees on the client's uplink — only TLS to the bridge:

```
docker compose -f docker/compose.yml exec client tcpdump -ni eth0 -c 50
```

## Usage

```
# server (Linux, needs TUN + NAT; see docker/server-entrypoint.sh)
belnet-bridge server -listen :443 -cert cert.pem -key key.pem -token SECRET

# client (Linux; see docker/client-entrypoint.sh for routes)
belnet-bridge client -url wss://bridge.example/ws -token SECRET
```

## Roadmap

1. MVP: tunnel, camouflage, Docker censorship demo (this repo).
2. Bridge distribution via BNS: publish bridge descriptors as encrypted BNS records, so users get bridges without a central list.
3. Masternode-hosted bridges and a `belnet --bridge` client mode built into BelNet itself.
4. Pluggable transports beyond WebSocket (QUIC/HTTP3, domain fronting via CDN).

## Status

MVP. Linux only (TUN). Not yet hardened: no rate limiting, a single shared token per bridge, IPv4 only.

# belnet-bridge

Experimental first-node transport:

```text
BelNet client → local UDP adapter → verified WSS → first BelNet node → BelNet route
```

The receiver runs on the first node and targets its fixed local IWP listener. BelNet retains encryption, identity and routing. Reachable entry addresses are supplied separately.

**Results:** a specific IWP filter blocked direct BelNet (0/3), while HTTPS delivered 10/10 steady requests. The subsequent 15-round adaptive experiment **did not achieve concealment**: 75 candidate evaluations, 14 policy changes, zero reductions in detection. Final DPI detected 32/32 BelNet flows; false positives were 12/128 synthetic controls. [Report](docs/EVOLUTION.md).

## Build and run

```sh
go build -o belnet-bridge .
go test -race ./...
go vet ./...
```

Set `BRIDGE_TOKEN` in both process environments. On the first node:

```sh
./belnet-bridge udp-server -target NODE_LOCAL_IP:1090 -cert entry.pem -key entry-key.pem
```

On the client:

```sh
./belnet-bridge udp-client -listen 127.0.0.1:2090 \
  -url wss://entry.example/ws -profile profiles/baseline.json
```

Add `-ca lab-ca.pem` for a private CA. Configure first-hop UDP redirection separately. `-profile` enables v2 framing and preserves the server UDP socket across WSS reconnects while both processes remain running. The baseline adds no padding or intentional delay. Full process restart recovery remains unresolved.

## Guide

- [Transport and routing](docs/NATIVE_TRANSPORT.md)
- [Threat model](docs/THREAT_MODEL.md) · [Integration](docs/INTEGRATION_PLAN.md)
- [Fifteen-round results](docs/EVOLUTION.md) · [Reproduce](lab/evolution/README.md)
- [Earlier official-release proof](docs/PROOF.md) · [Beldex reply draft](docs/RESPONSE_DRAFT.md)
- [Beldex grants reply, 20 Nov 2026](docs/BELDEX_REPLY_20261120.md)
- [Beldex proposal: value + DPI plan](docs/BELDEX_PROPOSAL_20261120.md)

The `client`/`server` TUN modes and `docker/compose.yml` retain the earlier L3 prototype, which uses a different architecture. No mainnet or real-ISP result is claimed.

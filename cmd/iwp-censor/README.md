# Initial IWP classifier for the private lab

Linux NFQUEUE enforcement of the public-key protocol test in [iwpdetector](../../internal/iwpdetector/README.md). It drops verified BelNet v0.9.8 initial IWP introductions and accepts other packets. Destination IP and port are not classification features. First-hop routing restrictions are separate firewall rules.

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o lab/iwp-censor-linux ./cmd/iwp-censor
iwp-censor -queue 42 -identities public-identities.txt -ready-file censor.ready
# In the isolated client's network namespace, after the listener is ready:
iptables -I OUTPUT -o eth0 ! -d 127.0.0.0/8 -j NFQUEUE --queue-num 42
```

Choose the helper architecture for the Docker host. Requires `CAP_NET_ADMIN` and kernel NFQUEUE support. Identity files contain one public 32-byte hex identity or `.mnode` address per line. The lab generates these from signed relay contacts; no secret keys are used. Do not install the example rule in the host namespace.

JSON output records verified drops, startup and final packet counters. Queue errors terminate the listener. No fail-open queue flag or `--queue-bypass` is enabled. A dead listener therefore does not silently become a successful bypass test.

Coverage is deliberately narrow: complete, unfragmented IPv4 UDP initial introductions to known public identities. It does not detect established IWP sessions, unknown identities, IPv6, or IP fragmentation. Nonmatching packets are accepted, including ordinary UDP and HTTPS. Fresh BelNet sessions and positive ordinary-traffic controls are needed for each experiment.

The listener uses [go-nfqueue v2.1.0](https://github.com/florianl/go-nfqueue/tree/v2.1.0). Parser tests feed a captured BelNet introduction through a constructed IPv4 packet and reject truncation, fragmentation and malformed lengths. Detector tests include the actual captured payload, mutations and random negative examples. These tests establish this protocol rule; they do not establish a population false-positive rate or resistance to other DPI rules.

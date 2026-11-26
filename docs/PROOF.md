# Real BelNet proof — 19 November 2026

**Result:** real `.bdx` HTTP traffic traverses a first-node HTTPS transport while a content-based IWP filter blocks direct BelNet. Reconnect continuity remains unresolved.

Official unmodified BelNet v0.9.8; six private relays, client and service; configured three-hop paths. WSS terminates on the actual first relay. No extra forwarding host or generic IP tunnel. Runtime image: `sha256:811e661c444e5e7b3a7511902c2c4b8a9e6b141fa785ffe1b9d64e3c342ee419`.

| Final run ID | Startup HTTP | Steady HTTP | Steady median / range |
| --- | --- | --- | --- |
| `20261119T025447Z-control` | 3 failures, 1 success | 10/10 | 51 ms / 43–65 ms |
| `20261119T025528Z-dpi` | 0/3 successes | — | — |
| `20261119T025556Z-dpi-tunnel` | 1 failure, 1 success | 10/10 | 59.5 ms / 44–82 ms |

The filter verifies the 224-byte IWP introduction tag against public relay identities, independent of destination IP/port. It dropped 12 introductions in direct mode; benign UDP and CA-verified HTTPS passed. The same filter with WSS dropped 33 direct attempts across the complete measurement, including outage/recovery; application traffic passed before the outage. No blanket UDP block applies. [Detector scope](../internal/iwpdetector/README.md).

**Disconnects:** zero established-session timeouts before outage. Both listeners stopped at 02:56:21 UTC and restarted at 02:56:51; both WSS connections returned at 02:56:53. Two established BelNet sessions timed out during the outage; all eight recovery HTTP probes failed through 02:57:46. Overall logs record four path-build timeouts, 12 client peer-deregistration events and 44 pending-session timeouts. Measurement ended at 02:57:48.934890785. Later classifier-teardown effects are recorded separately.

**Independent audit:** all 11 successful HTTPS-run nonces match the service log; none appears in plaintext in eight captures. Captured client IPv4: 1,506 TCP/443 packets plus two intentional benign UDP/1099 packets; zero native UDP/1090 and zero kernel capture drops. Three hops do not guarantee distinct relays: 5/8 client and 4/6 service paths used three distinct identities. Requests are not mapped to individual paths.

## Reproduce and inspect

Follow [lab instructions](../lab/README.md), then run `./lab/run.sh control`, `./lab/run.sh dpi`, `./lab/run.sh dpi-tunnel` with its default outage test enabled. See [full results](../lab/RESULTS.md), the [final tunnel manifest](../lab/results/20261119T025556Z-dpi-tunnel/manifest.txt) and [independent audit](../lab/results/20261119T025556Z-dpi-tunnel/independent-audit.json). Extract the evidence archive into `lab/results/` to preserve these paths. The optional [collector](collect-evidence.sh) retains manifests, hashes, requests, logs, counters, benign controls and captures; key/configuration files are excluded.

**Limits:** small private network, whitelist disabled, amd64 emulation. No mainnet admission, national-censor resistance or browser-HTTPS indistinguishability claim. Automatic application recovery is not solved.

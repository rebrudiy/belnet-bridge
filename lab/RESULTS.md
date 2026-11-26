# Native first-hop proof — 19 Nov 2026 UTC

Final runtime image: `811e661c444e5e7b3a7511902c2c4b8a9e6b141fa785ffe1b9d64e3c342ee419`. Official unmodified BelNet v0.9.8; six private relays and two clients. HTTPS terminates on the actual first relay.

| Scenario | Warmup HTTP | Steady HTTP | Median | Established session timeouts, all eight nodes |
|---|---:|---:|---:|---:|
| Native control | 3 failures, 1 success | 10/10 | 51 ms | 0 |
| Cryptographic IWP filter, direct | 0/3 | — | — | 0; no client session established |
| Same filter + first-hop HTTPS | 1 failure, 1 success | 10/10 | 59.5 ms | 0 before outage; 2 during outage |

The direct DPI run dropped 12 verified IWP Intro packets. The HTTPS run dropped 33 direct attempts across its full measurement, including the outage. Ordinary UDP echo and CA-verified HTTPS passed in both DPI runs. Neither DPI mode uses a blanket UDP block.

Independent audit confirmed all 11 successful HTTPS-run nonces in the service log, no nonce plaintext in eight wire captures, 1,506 TCP packets on port 443, two deliberate benign UDP packets on port 1099, zero native UDP/1090 packets and zero kernel capture drops. The TLS-only claim applies to BelNet traffic.

Native paths are configured for three hops. Of eight client paths built, five used three distinct relay identities; of six service paths, four did. Some paths repeat an identity in this small topology. Individual HTTP requests are not attributed to a specific path.

Both HTTPS listeners stopped for 30 seconds at 02:56:21 UTC and restarted at 02:56:51. Both WebSockets reconnected at 02:56:53. HTTP failed during the outage and in all eight recovery probes over the next 57 seconds. The captured node logs contain two established session timeouts, four path build timeouts, ten path build failures, 12 peer deregistration events and 44 pending session timeouts. Pending failures are separate from established disconnects. Native entries can retain the old client identity/source address for five minutes.

Measurement ended at `02:57:48.934890785Z`, derived from the classifier summary. Subsequent ping disconnects at 02:57:58 followed intentional classifier teardown; their extended logs are preserved separately. No raw logs or captures were filtered. Conventional medians and all-node event totals were recomputed from the recorded files after the run.

Final evidence only:

- `results/20261119T025447Z-control/`
- `results/20261119T025528Z-dpi/`
- `results/20261119T025556Z-dpi-tunnel/`

The archive `results/native-firsthop-poc-20261119.tar.gz` includes these three directories, independent audits and these instructions. Earlier runtime results remain separately preserved. Reproduce with [README.md](README.md).

Limits: private network, whitelist disabled, no mainnet stake validation; small sample under amd64 emulation, no national-censor measurement or browser-HTTPS indistinguishability claim. Mainnet needs a cooperating registered first-hop operator. IWP continuity after reconnect remains unresolved integration work.

# Fifteen rounds: results

19 November 2026. **The wrapper remained detectable.** Each round retrained a random forest on encrypted TLS record sizes, directions and timing, then tested the incumbent and four new padding/batching/pacing/dummy policies on actual private BelNet requests.

| Measurement | Result |
| --- | ---: |
| Retrained round models / candidate evaluations | 15 / 75 |
| Accepted policy changes / reduced detection rate | 14 / 0 |
| Independent final attacker: detected BelNet flows | 32/32 |
| False positives on synthetic controls | 12/128 = 9.375% |
| Calibration false-positive budget | 5%; exceeded on final test |
| Final BelNet requests / control workloads | 16/16 / 64/64 |
| Successful HTTP latency | Median 181 ms; range 113–485 ms |
| TLS socket bytes / UDP payload, aggregate | 3.005×; includes TLS startup, excludes IP/TCP headers |

The final attacker had 128 trees and depth 8. Training and test workload groups did not overlap. The nominal 95% false-positive interval is 5.44–15.67%; paired flows and shared relays limit its interpretation.

**Detection differs from denial.** Inline decisions closed TCP connections after two seconds or 64 records. Reconnection preserved application success, including the after-window probe. Final cohorts used shadow decisions: 12 false positives do not mean 12 physically blocked controls.

## Evidence and errors

[Every round](../lab/evolution/results/full-15-queuefix-20261119/RESULTS.md) · [Frozen policy](../lab/evolution/results/full-15-queuefix-20261119/frozen-profile.json) · [Final measurements](../lab/evolution/results/full-15-queuefix-20261119/final.json) · [Independent audit](../out/verification/evolution-independent-audit.json).

Independent replay reproduced all 16 models byte for byte before and after refactoring, replayed 75 candidate metrics, matched 282 successful nonces to service logs, and matched 962 TLS record-length sequences to PCAP. Socket-callback times are not packet-arrival times.

The controller stopped after measuring round 15 because the incumbent exceeded the byte budget. Recovery selected an already measured feasible candidate; original data and failed status remain preserved alongside completed recovery status.

Native logs contain **1,495 pending-session timeout lines** during measurement and zero established-session timeout/path-failure/deregistration lines. Six established-session timeouts occurred after measurement ended. These are log-line counts, not unique outages. [Times and patterns](../out/verification/evolution-native-log-audit.json). Failed warmups remain recorded.

## Scope and code

Controls are four synthetic local WebSocket families, not representative browser HTTPS. Fixture timing may aid classification. This is one classifier family and a small private topology; no ISP result.

Runtime: BelNet `480aafb3`, **TESTNET=ON**, plus a disclosed [one-line queue-wakeup patch](../build-lab/queue-wakeup.patch). Failed unmodified cold starts remain recorded. This differs from the earlier official-release proof. [Build provenance](../build-lab/README.md).

Transport/session code is in `udp*.go`; framing/scheduling in `internal/shaping`; observation/classification in `internal/traffic`; strict profiles/headers in `internal/wireconfig`; live optimization in `lab/evolution`. Refactoring separated client/server experiment state and repaired lease cleanup. Race tests and vet pass. A separate [production CLI check](../out/verification/production-profile-smoke.json) passed 12/12 byte-exact datagrams with experiment controls disabled.

[Protocol](EVOLUTION_PROTOCOL.md) · [Reproduce](../lab/evolution/README.md). The selected policy is evidence, not a recommended concealment setting.

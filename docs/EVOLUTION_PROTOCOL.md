# Fifteen-round experiment

Protocol fixed before the main run. The first main search/workload seed was `20261119015`; that run failed during network warmup, before optimization or final-test acquisition. Its artifacts are retained. The renewed main seed is `20261119016`, distinct from integration pilots. This is a private-lab experiment, not a claim about an ISP or browser traffic.

**Traffic:** genuine BelNet v0.9.8 requests to a `.bdx` service, with random nonces. Controls are live chat/telemetry/transfer-style WebSocket workloads. Both classes use the same Go TLS implementation, certificates, endpoints and request-header lengths. Separate clients and source-workload groups supply train, validation and final test data.

**Runtime amendment before the renewed main run:** cold-start routing also failed with an unmodified native ARM build. The next cold pilot uses source `480aafb3`, `TESTNET=ON`, plus the [one-line queue wakeup patch](../build-lab/queue-wakeup.patch): call the existing router pump after successfully enqueueing an outbound message. This changes scheduling, not packet formats or cryptography. The renewed main run may start only after that pilot passes. Both unmodified binaries and failed runs remain available; this is a different runtime from the earlier official-release proof.

**Attacker:** a CART random forest over server-observed encrypted TLS record sizes, directions and times. Its prefix ends after two seconds or 64 records. Plaintext, addresses, certificates, labels and profile identifiers are excluded. Fifteen models retrain on all accumulated training data; thresholds use benign validation only.

**Defender:** each round evaluates the incumbent and four mutated bidirectional profiles. Padding, batching, pacing, jitter and dummy traffic change real transport behavior. Every candidate carries actual BelNet requests. Selection minimizes detection, then score and transport cost, subject to delivery and cost limits. An unsuccessful mutation remains in the evidence.

Each round also runs one fresh positive and one benign group with inline enforcement. Semantically equivalent policies are deduplicated before evaluation; unused parameters do not count as wrapper changes.

| Fixed main-run setting | Value |
| --- | --- |
| Benign train / calibration / final test | 64 / 64 / 64 workload groups |
| Initial BelNet training | 12 groups |
| Candidate evaluation | 2 fresh validation groups per profile |
| New selected-profile training | 4 groups per round |
| Calibration FPR budget | 5% per flow; also report group-level FPR |
| TLS socket bytes / native UDP payload | At most 8× for selection |
| Successful request latency | At most 10 seconds |
| Scheduler-added delay | At most 100 ms, excluding blocked writes |

After round 15, freeze the profile. Collect 12 fresh training groups for it, fit an independent 128-tree/depth-8 attacker, then evaluate once on 16 fresh positive and 64 benign final-test groups. Test data must never enter training or selection.

Report each round as `Aᵢ(Dᵢ₋₁) → Aᵢ(Dᵢ)`, with exact counts, costs and HTTP results. Compare consecutive attackers on the same fresh incumbent observations. A new model or profile is an update; a measured improvement requires the corresponding metric to improve. Fifteen rounds do not imply fifteen wins.

An inline positive verdict closes the actual encrypted connection. Detection, connection closure and application failure remain separate outcomes: an HTTP request may finish before the prefix decision or survive through reconnection. Retain incomplete observations and infrastructure failures separately; never count a missing capture as successful evasion. Confidence bounds are exploratory because paired flows and shared relays are correlated.

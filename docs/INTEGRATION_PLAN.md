# BelNet integration proposal

19 November 2026. Same-node HTTPS transport passed a real private BelNet v0.9.8 experiment against an IWP-introduction filter. [Accepted results](PROOF.md). Mainnet and ISP operation are unverified. No packaging agreement is recorded.

**Target:** `BelNet client → HTTPS transport → first BelNet node → BelNet route`. The UDP target is that first node's listener; no extra forwarding machine. Legacy L3 modes remain separate.

| Step | Work with Beldex / maintainers | Output / status |
| --- | --- | --- |
| 1. Confirm interface | Review IWP addressing, identity, bootstrap, peer admission and private ingress versus RouterContact publication | Private fixture works; production compatibility decisions remain open |
| 2. Review evidence | Inspect image/binary hashes, nonces, captures and all failures | Direct control 10/10 steady; direct DPI 0/3; DPI+HTTPS 10/10 steady. Full startup and outage failures retained |
| 3. Repair continuity | Preserve or resume UDP/IWP state across WSS reconnect; review client identity and local redirection | Historical full restart: HTTP recovery 0/8. V2 retains UDP associations across WSS rotation; process restart remains open |
| 4. Evaluate scaling/camouflage | Load-test peer/session limits and compare transport profiles against independent classifiers | Same-node sockets use separate ports but one source IP; upstream per-IP path-build limits can aggregate clients (~500 ms). Not production-proven |
| 5. Package | Agree credentials, certificates, platforms, defaults, updates and regression ownership | Optional BelNet-adjacent package first; in-process component subject to review |

**Packaging:** the author is willing to discuss shipping the code alongside BelNet and the associated support terms. The final distribution, maintenance and support arrangement remains to be agreed. Current code is MIT-licensed; preserve notices and review dependency/BelNet licences for the chosen distribution.

**Adversarial ML:** [15 rounds completed](EVOLUTION.md): 75 candidate evaluations, 14 policy changes, no reduction in detection. Final detection was 32/32; false positives 12/128, above the 5% calibration budget. The private TESTNET runtime includes a disclosed scheduler patch. Review fixture timing and broaden controls before choosing production shaping defaults.

**Engineering call:** review evidence and first-node questions, agree the next patch and maintenance owner. The author has not selected a slot. Nothing has been sent or booked.

Sources: [usage](NATIVE_TRANSPORT.md), [proof](PROOF.md), [threat model](THREAT_MODEL.md), [licence](../LICENSE), [upstream path-build limiter](https://github.com/Beldex-Coin/belnet/blob/v0.9.8/llarp/path/pathbuilder.cpp).

# TLS metadata classifier

The adaptive lab's attacker uses a seeded CART random forest, trained on real
session observations. This package contains no hardcoded BelNet traffic rule.

`ObserveConn(raw, clientSide, recorder)` wraps a TCP connection **before TLS**.
The recorder reconstructs outer TLS records from fragmented reads/writes and
retains only type-23 record lengths, directions and relative completion times.
It stores no ciphertext payload or plaintext. TLS 1.3 encrypted handshake records
also have outer type 23. Features use at most 64 records over two seconds.

The 80 fixed features cover directional sizes/counts, timing, bursts and the first
24 signed lengths and gaps. IPs, ports, certificates, class labels, profile IDs,
session IDs and wall-clock timestamps do not enter the feature vector.

`Fit(config, train, benignValidation)` retrains on caller-supplied history and
calibrates a strict `score > threshold` rule within the empirical validation FPR
budget. It rejects test-split training and training/validation group overlap.
Both entry connections and variants of one workload belong to one `GroupID`.
The caller must keep final test observations outside all fitting and selection.

`Model.Score`, `Model.Block` and `Evaluate` share the online feature extractor.
`Save`/`Load` preserve the model and schema. `WireBytes` counts raw socket bytes
for overhead measurements, including handshakes and post-window traffic; TCP/IP
headers and retransmissions require the separate packet capture.

Evaluation reports confusion counts, TPR/FPR and nominal binomial intervals.
Small or correlated samples cannot establish production false-positive rates.
No separation is fabricated when the FPR constraint requires allowing all flows.

The causal live-traffic constraint follows [Nasr et al., USENIX Security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/nasr).
Defense-aware retraining follows the evaluation principle in the [2023 SoK authors' code](https://github.com/critical-wf-sok/Efficient-Defense-Evaluation).

# DPI / wrapper experiment

The controller trains a TLS-metadata classifier, tests four wrapper mutations and the incumbent, then keeps the best feasible profile. It repeats 15 times. After freezing the wrapper, a fresh attacker acts last on unseen sessions.

Components: six private BelNet relays, one `.bdx` service, separate train/validation/test clients, same-node HTTPS transport, a server-side classifier and continuous packet capture. The final client starts only after freezing and final-attacker training.

Fresh ARM64 reproduction from the repository root ([build details](../../build-lab/README.md)):

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o docker/belnet-bridge .
BB_FRESH_IMAGE=belnet-bridge:reproduction bash build-lab/build.sh queuefix
export BB_IMAGE=belnet-bridge:reproduction BB_PLATFORM=linux/arm64
export BB_BELNET_BUILD='source480aafb3c68ac359f0711b2cbd8a07be661703c0 TESTNET=ON endpointO0 queuefix83f1339d42e96c30d814a29ec8505c4d3285a5bddf46266a2b0a3d728623bfe6'
BB_RECOVERY=0 ./lab/run.sh control
./lab/evolution/setup.sh
go run ./lab/evolution/cmd/evolve -rounds 15 -seed 20261119018 -out lab/evolution/results/NEW_RUN
./lab/evolution/stop.sh results/NEW_RUN/runtime
```

Transport and benign helper must use the same Go architecture.

Each run records source archives, binary hashes, models, policies, nonces, failed/rejected trials, byte counters and held-out coverage. JSON artifacts/statuses commit atomically. A final-selection checkpoint can resume without resampling using `-resume-final-round DIR`; used final tests cannot reopen.

Limits: four synthetic matched WebSocket families, two-second TLS observation, private TESTNET topology and a disclosed one-line BelNet scheduler fix. Detection and TCP resets are separate from application success. This does not establish browser indistinguishability or ISP resistance. See the root overview for the historical results.

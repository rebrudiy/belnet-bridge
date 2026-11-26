# G03 collector

Measures one fresh B1 cohort: 71 train/validation sessions, 24 frozen mixed batches,
80 seconds per session from a VM timestamp before launch. Capture continues for
2 seconds of prefix grace. Every initial TLS connection and reconnect belongs to
the primary inspection scope. B2 acquisition is deliberately unavailable until a
final transport/model gate is implemented.

```sh
node lab/dpi-g03/runtime/prepare.cjs --directory lab/dpi-g03/run/prepared-b1-v2
node lab/dpi-g03/runtime/freeze.cjs --prepared lab/dpi-g03/run/prepared-b1-v2/preparation.json --output lab/dpi-g03/run/freeze-b1.json
node lab/dpi-g03/runtime/tools.cjs --master lab/dpi-g03/run/freeze-b1.json --output lab/dpi-g03/run/defender-freeze-b1.json
node lab/dpi-g03/runtime/collect.cjs --freeze lab/dpi-g03/run/freeze-b1.json
```

Existing paths are never overwritten. A failed attempt stays in the cohort;
there is no automatic retry or replacement. Preparation uses network-none
containers for keys/configuration checks. Only `collect` starts B traffic.

The common observer is a bounded TCP443 PCAP on the Docker CONNECT proxy's
upstream interfaces. Native UDP1090 leakage and receiver UDP are separate
auxiliary evidence, excluded from DPI features. Chrome starts with a fresh
profile and explicit loopback CONNECT proxy. Public certificate validation stays
normal; private fallback uses its exact frozen lab SPKI. HTTP3 is outside scope.

Ordinary matched sessions and native sessions attempt a real initial RPC at0s,
then RPC at5/15/25s and a45s workload at35s. Long ordinary sessions run80s.
Each nonce and workload seed is frozen. Initial native RPC can fail while routes
build; that application failure is retained and does not invent a capture fault.

`observer-index.json` carries acquisition-quality problems to the defender:
missing counters, forced cleanup, cap hits and unexplained packet accounting
mismatches cannot become nondetection successes. App outcomes, capture coverage,
rule eligibility and classifier decisions are separate measurements.

The collector temporarily replaces only the existing lab Go443 listeners. It
archives exact argv/environment/cwd privately and checks restoration. Existing
native C++ nodes stay alive. It removes only its own `bb-g03-*` containers.
Do not publish `run/`, Chrome NetLog/profile, credentials or the private test
seed vault. The master freeze records the vault commitment before B1; its test
seeds remain unused until a later policy freeze.

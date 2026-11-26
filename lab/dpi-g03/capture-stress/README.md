# Finite capture A/B stress — DEV only

Exactly two cases, one attempt each: buffered16MiB (`-B16384`) then
immediate64MiB (`--immediate-mode -B65536`). No sweeps/rerolls. Both qualify:
choose buffered16 for lower kernel memory. Only one qualifies: choose it.
Neither qualifies: **NO Q/full B1**. Source, actual helper/image/config hashes,
new nonces and this selection rule are frozen before starting the own bridge.

Both cases run the same16MiB HTTPS burst at500ms while a5s small RPC/WSS
workload is ongoing. Same deterministic seed/cadence/body sizes, fresh nonce/TLS
sessions per case. Server computes actual body SHA; client independently hashes
received bytes and compares the preregistered Node-periodic golden SHA. Exact
client/server WSS counts and RPC verification are checked. Client must complete
its5s interval; server duration flag is preserved separately (a millisecond
close edge is not silently rewritten).

Exactly2 own containers on one `--internal` bridge10.179.61.0/24, no host ports,
public network or existing nodes. Server namespace alone owns loopback alias
10.88.0.11; client namespace has only a /32 route via own server. This preserves
immutable allowlisted proxy8e1… without overlapping Docker network prefixes.

Capture-v4 is imported unchanged. Its spawn/signal adapter runs tcpdump via
`docker exec` inside the client, with recorded PID and comm check; SIGUSR1/INT/KILL
never stop the client namespace or create a third container. Actual argv and
signal calls are recorded. Proxy is quiesced via its loopback control; wait at
least500ms VM time, obtain two stable exact zero-drop live statistics snapshots
within2.5s, then SIGINT/final epoch and strict raw-PCAP count comparison.

Qualification requires functional SHA/exact16MiB+WSS proof, matching server
nonce/counts, quiesce success, VM wait>=500ms, live drain complete, fresh complete
final stats, no kernel drops/cap/forced stop/errors, final captured==received==raw
PCAP count and no truncated packets. Host capture hard cap64MiB per case. Both
failures remain evidence; no parameter changes after observing either case.

All resources are named `bb-g03-capstress-dev-01*` and removed afterward. Private
TLS key/configs stay in ignored `run/dev-01/private`; no trust-store edits.
This is capture load qualification, not native BelNet/DPI evasion proof.

Run: `node lab/dpi-g03/capture-stress/run.cjs` once. Refuses existing dev-01 paths.

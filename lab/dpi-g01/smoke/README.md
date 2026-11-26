# Isolated actual REALITY smoke

This is a UDP echo fixture through the frozen Go stream adapter and real pinned
sing-box REALITY/TCP cores. It is **not a BelNet proof or public HTTPS camouflage**.
The existing Stage A native deployment, entry namespaces and frozen runtime sources
are not used or modified. One new container has Docker `--network none`, 1 CPU,
512 MiB and only two sing-box core processes.

A manifest with actual adapter/helper/config/source hashes is written before
starting listeners. Configs derive from prepared-a entry1, preserving credentials,
uTLS Chrome, REALITY and fixed TCP routing. Only loopback addresses change.
A local UDP echo target12090 replaces native IWP1090 explicitly.

```sh
node lab/dpi-g01/smoke/run.cjs UNIQUE_RUN_ID
```

The helper retains one UDP socket while testing exact0/1/1200/60000/65507-byte
roundtrips before and after a client-core restart with2s absence. Server/client
Go adapter processes remain alive. It also checks a second UDP source creates
a distinct SID/socket, and an invalid inner token creates no UDP state. Every
attempt, including errors, is retained; no reroll-until-success.

Ciphertext capture filters only loopback TCP19444. It excludes plaintext21990,
which carries the inner token/SID. Private configs remain in ignored run data.
Outputs and SHA-256 index: `out/dpi-g01/smoke/ID/`. Only the owned smoke container
is removed. Overall wait90s bounds collection; no native traffic is generated.

# R2 collector

New revision after the finite15-session G03 collector checkpoint. Previous
sources, manifests, results and failed qualification remain intact.

The observation horizon is80 seconds from a prelaunch VM timestamp. At82 seconds
(2 seconds of flow-prefix grace), the proxy permanently closes upstream tunnels
and rejects new CONNECT requests while keeping its process/namespace alive.
Capture drains for at least500ms, then stops. Capture packet accounting and TCP
reassembly determine completeness. Proxy-forwarded bytes remain a separate
measurement: post-horizon records received during intentional closure can appear
on wire without being delivered through the proxy; they are not silently removed.

Run the finite3-session diagnostic qualification first. It uses fresh `q-`
identifiers/nonces and split `development`; fitting is forbidden. It consumes no
B1/B2 nonce or sealed test value.

```sh
node lab/dpi-g03/runtime-v2/prepare.cjs --directory lab/dpi-g03/run/prepared-b1-r2
node lab/dpi-g03/runtime-v2/freeze.cjs --stage Q --assignments lab/dpi-g03/qualification-r2.json --prepared lab/dpi-g03/run/prepared-b1-r2/preparation.json --output lab/dpi-g03/run/freeze-q-r2.json --run-id q-r2-20261119
node lab/dpi-g03/runtime-v2/collect.cjs --freeze lab/dpi-g03/run/freeze-q-r2.json
```

Only after qualification and a new B1 freeze:

```sh
node lab/dpi-g03/runtime-v2/freeze.cjs --prepared lab/dpi-g03/run/prepared-b1-r2/preparation.json --assignments lab/dpi-g03/assignments-r2.json --output lab/dpi-g03/run/freeze-b1-r2.json
node lab/dpi-g03/runtime-v2/tools.cjs --master lab/dpi-g03/run/freeze-b1-r2.json --output lab/dpi-g03/run/ensemble-freeze-b1-r2.json
node lab/dpi-g03/runtime-v2/collect.cjs --freeze lab/dpi-g03/run/freeze-b1-r2.json
```

No existing preparation/output is overwritten. B1 has71 fresh physical sessions,
24 mixed batches, at most3 active sessions/one native client and no paired source
plans in the same batch. All attempts, app failures and capture failures remain.
The original committed test vault is reused without decoding its values before
the final policy freeze. B2 acquisition remains unavailable until that gate exists.

`STOP_AFTER_BATCH` in the run directory or one SIGTERM/SIGINT stops after the
current finite batch and performs normal archive/restoration. The collector
restores the exact saved old Go443 argv/environment and verifies its PID/listener;
existing C++ nodes are never restarted. Only owned containers are removed.

DPI inputs are upstream TCP443 PCAP from the same CONNECT observer for both
classes. Auxiliary native UDP capture/firewall counters, SID/session hashes and
nonce proof are functional evidence, excluded from classifier features. Chrome
uses a fresh profile; HTTP3 is excluded. Sources: [R2 protocol](../PROTOCOL-R2.md).

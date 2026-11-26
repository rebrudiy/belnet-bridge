# Threat model

19 November 2026. The native first-node UDP/WSS path passed a private BelNet v0.9.8 content-filter experiment. [Proof and failures](PROOF.md). No mainnet/ISP result. Legacy L3 modes remain separate.

**Scope:** reachable entry IP, pre-issued access parameters and authenticated HTTPS. Address distribution and replacement after IP blocking are deferred.

| Observer | Protected content | Still visible |
| --- | --- | --- |
| Client ISP | HTTP path, token and datagrams under verified TLS | IPs, ports, timing, sizes; exposed DNS/SNI and fingerprints |
| Entry operator | Other-hop keys and end-to-end payload remain protected by BelNet | Client IP, token, its own BelNet state, adjacent connections and metadata |

TLS/cover pages do not prove browser indistinguishability. Compromised clients and multi-point correlation remain outside protection.

| Event | Consequence | Current control / remaining work |
| --- | --- | --- |
| Address disclosed | Scanning and IP/SNI blocking; no automatic decryption | Address replacement is separate work |
| Token disclosed | With address/path, outsiders confirm/use the tunnel | Rotate shared token, affecting all clients. It does not decrypt other sessions |
| Entry compromised | Local secrets, client metadata and delivery exposed | No anonymity promise against entry operator |
| False TLS server | Token/datagrams exposed if trusted | WSS/TLS 1.3, name/CA verification; redirects disabled |
| Transport/bootstrap fails | Loss of service or unexpected direct traffic | Adapter has no raw-UDP fallback; production DNS/IPv6/bootstrap still need review |

**Observed outage:** a 30-second stop restored WSS two seconds after restart, but HTTP remained 0/8 in recovery probes. Two established BelNet sessions timed out during the outage. That historical run predates v2 retained associations. V2 preserves the UDP socket during WSS rotation within running processes; full process restart continuity remains unresolved. Earlier diagnostics reported `too many session`; upstream code retains non-public inbound sessions for five minutes. This is the proposed continuity explanation, not an exact error line from the final INFO logs.

**Bounds:** fixed destination; per-session UDP socket; 64 server sessions/64 local peers/64-datagram queues; deadlines. These are not bandwidth limits. The local UDP sockets have separate ports but the same entry-local source IP; upstream per-IP path-build limits can aggregate clients. Load/admission review remains necessary.

**Logging:** native events/errors may include endpoints; no “no logs” claim. Legacy L3 logs client IPs and exposes destinations/plaintext non-BelNet traffic to its operator. Ordinary RouterContacts publish addresses; HTTPS alone does not make an entry private.

Evidence: [implementation](../udp.go), [IWP detector limits](../internal/iwpdetector/README.md), [session lifetime](https://github.com/Beldex-Coin/belnet/blob/v0.9.8/llarp/iwp/session.cpp), [RouterContact publication](https://github.com/Beldex-Coin/belnet/blob/480aafb3c68ac359f0711b2cbd8a07be661703c0/llarp/router/router.cpp#L970-L995).

**Adaptive classifier:** the [15-round experiment](EVOLUTION.md) detected 32/32 final BelNet flows and marked 12/128 synthetic controls. HTTPS protects content, not sizes, timing or recognizability. Lab model/control endpoints are opt-in and literal-loopback only; production profile operation does not require them.

**Broader controls and experimental v3:** the [new evaluation](../lab/dpi-v2/RESULT.md)
includes real Google/YouTube sessions, matched non-echo workloads, fifteen explicit
rule hypotheses and a mature REALITY baseline. The old forest marks101/101 new
held-out benign flows: its old echo-only false-positive result did not generalize.
V3 cell sizes, bursts, polling and padding remain traffic-analysis features;
fragmentation is not an anonymity guarantee. Retaining a UDP socket preserves
its address while processes live, but does not prevent native session/path
timeouts during a long block. The live30-second deny tests include failed
application recovery. Full process restart continuity remains unresolved.

**Experimental framed mode (G01):** [the new protocol](../lab/dpi-g01/PROTOCOL.md)
uses an external REALITY/VLESS core and a same-node UDP/stream adapter.
The adapter itself adds no encryption. Its plaintext TCP listeners and client
upstream must be literal loopback addresses; the outer core protects the
network connection. The entry operator can associate that connection with
local UDP state and still sees the client's IP. BelNet encryption is unchanged.
In G01 A, two fresh private TESTNET deployments delivered 16/16 candidate phase
requests, including fresh requests after a two-second core interruption, while
the adapter/native processes and receiver UDP tuples stayed unchanged.
The [independent audit](../out/dpi-g01/root-review/stage-a-r2-audit-accounting.json)
checks nonce, process and tuple evidence. This does not establish recovery after
a prolonged outage or DPI evasion; those require separate measurements.

The REALITY public key is public configuration. VLESS UUID and the adapter
token are access credentials. The adapter validates its token before creating
UDP state, retains at most 16 sessions in the CLI, and uses a random 256-bit SID.
Token holders share a principal; SID is not an independently authenticated user.
Through an authorized outer connection, possession of both the token and another
live SID permits replacing that attachment. Credentials do not automatically
decrypt other recorded sessions.
Address disclosure still permits IP blocking. Credential rotation and full
adapter restart continuity are separate operational work.

Only explicit `-lab-control` enables framed packet metadata. It records times,
sizes, tuples and a session hash, with bounded history and a truncation flag;
it is not a no-logs guarantee. Packet payloads, tokens and raw SIDs are omitted.
Loopback access and node-local compromise remain outside transport protection.
The [implementation](../udp_stream.go) retains the receiver's UDP socket while
the adapter lives. This does not preserve expired native cryptographic state:
the inspected upstream has a 25-second ordinary alive timeout and a five-minute
inbound nonpublic-client timeout. A two-second core restart and a prolonged
outage must therefore be tested and reported separately.

The [A2 experiment](../lab/dpi-g02/RESULT.md) adds opt-in client queue expiration.
It limits age at the start of a local adapter write, with explicit packet loss;
it does not bound buffering inside the core, network delivery or total latency.
All32 phase requests succeeded in four private development deployments, while
7 datagrams/3070 bytes expired. Default retention remains unchanged. This is a
delivery/freshness result, not evidence of resistance to an admissible DPI policy.

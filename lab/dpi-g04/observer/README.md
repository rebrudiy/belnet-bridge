# G04: outer TLS header availability (offline SHADOW)

CLI: `observer -pcap FILE -meta GROUP.json -out WINDOWS.json`. Schema6, version `g04-header-observer-v1`. Reuses the G03 v4 TCP/PCAP parser and bounded-window proofs in a separate source tree. G03 artifacts remain unchanged.

An event is emitted after all5 valid TLS23 header bytes become contiguous. `raw_ns` is the maximum availability timestamp of those bytes and the required earlier TCP prefix; `ordinal` is the header callback ordinal. `bytes` is **declared body length+5**, never a claim about delivered ciphertext bytes. Later body delivery cannot move an existing header event. The parser skips the declared body before parsing another header.

| Final stream state | Header view |
|---|---|
| Complete header, complete body | Header evidence |
| Complete header, open partial body | Header evidence; `open_body_in_progress` diagnostic |
| Complete header, partial body with verified FIN/RST prefix | Header evidence; `partial_body_known_abort`, without a complete TLS-session claim |
| Valid1..4-byte partial header, verified direction FIN/connection RST and TCP census | Unsupported evidence/abstention, no event or invented anchor |
| Partial header without verified close; gap/conflict/malformed/censor/missing handshake | UNKNOWN |

`first_tls23_header_available_utc` and `group_first_tls23_header_available_utc` replace the old body-completion names. Per-flow `tls23_headers`, `primary_tls23_headers`, `total_tls_record_headers`, `tls_streams`, `issue_timestamps`, census/header-parser flags and raw TCP counters expose the supporting metadata. Retained ciphertext bytes are never exported.

`tcp_sequence_census_complete` and `tls_header_parse_valid` alias explicit `primary_tcp_sequence_census_complete` / `primary_tls_header_parse_valid`. Their scope ends at `primary_evidence_ends_utc`: the later of the primary end and a required in-horizon first-prefix end. Separate `whole_capture_*` flags retain later faults. Stream header-start/available/close UTC and `partial_header_relevant_to_primary` keep postprimary diagnostics from erasing earlier evidence.

`header_evidence_absent` permits a null anchor for validated primary attempts with no TLS23 header, including handshake22/alert21 traffic and verified closed partial headers. Explicit primary start and a captured primary initial SYN are required; actual flow identities stay in the denominator. This flag supplies no classifier feature and does not prove stealth. Consumers must independently validate its supporting inventory and stream fields.

TCP proof remains strict: pending gaps, malformed/truncated packets/PCAP, causal faults, consumed/pending overlap conflicts, ACK beyond captured contiguous bytes and inconsistent close sequence remain UNKNOWN. FIN consumes one sequence number; a half-close terminates only its direction. Exact consumed-byte history is bounded globally by the256MiB PCAP cap per pass, so old retransmissions do not acquire a64KiB age cutoff. The bound is logical retained bytes, not a resident-memory promise; Go allocations and two-pass working memory add overhead.

The fixed scope remains80s from prelaunch VM start,11 two-second offsets `[0,8,16,24,32,40,48,56,64,72,78]`, all in-horizon initial/reconnect prefixes, plus2s declared grace. Source PCAP order/timestamps are preserved. True-min discovery and earliest64 selection require a seekable two-pass PCAP: **this is SHADOW analysis, not an online censor**.

New coverage/ordering contracts are in the adjacent JSON files and pinned by SHA. Opposite-direction header ambiguities mask r05/r06/r10/r15 and companion LF05; unrelated evidence remains available. No TLS keys or application payloads are required/exported. No actual cohort extraction, classifier fitting, live enforcement or network collection occurs in preparation.

Build/check: `node lab/dpi-g04/observer/build.cjs` from repository root. It runs synthetic race/vet checks, archives source and emits versioned Darwin/Linux ARM64 binaries and TOOLING.json. The companion longflow parser is derived by its `sync-parser.cjs` and independently checked against the same fixtures.

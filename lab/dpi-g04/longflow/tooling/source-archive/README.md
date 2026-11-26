# G04: full80s header metadata

CLI: `longflow -pcap FILE -meta GROUP.json -out LONGFLOW.json`; `-catalog -out CATALOG.json` needs no PCAP. Schema4, version `g04-header-longflow-v1`.

The companion uses the same new header parser as [observer](../observer/README.md), derived by `sync-parser.cjs`; source baselines, contracts and binaries are pinned. G03 remains immutable. Every primary TLS23 **header** contributes once, without the64-event window cutoff. Sizes mean declared body+5, not delivered bytes; timestamps mean complete header availability, not body completion.

The six scalar formulas remain: exact26 share, tiny≤64 share, normalized declared-length concentration, duplex declared-byte balance, within-flow immediate-reply share and directional regularity. Support thresholds stay unchanged; the new definitions SHA explicitly binds the new header units. Adjacent/pair/gap statistics never join different TCP flows. Ambiguous opposite-direction header ordering masks LF05.

Applicability is exactly `primary_tls23_headers > 0`. A genuinely preprimary first-header pointer and before-primary counters remain diagnostics; they do not discard headers available inside80. A preexisting flow with0 primary headers retains its identity and cannot invent eligible features.

Flow/stream diagnostics, first-header times, `header_evidence_absent`, census flags and `issue_timestamps` are copied from the observer. Open bodies and verified aborts are diagnostics, not complete TLS sessions. Valid no-header attempts retain their actual flow identity and abstain rather than acquire zero-valued classifier evidence. Header/prefix/capture/provenance errors remain UNKNOWN.

`declared_tls_record_bytes` and directional variants distinguish the size statistic from transport byte costs. `primary_tls23_headers` and before/after/whole-capture counts label the evidence unit. Native UDP/app delivery, raw-wire cost and live censor enforcement require separate proofs.

Build/check: `node lab/dpi-g04/longflow/build.cjs`. This performs source derivation, synthetic race/vet checks, source archives and versioned Darwin/Linux ARM64 builds. No actual cohort reads, fitting, Docker or network acquisition are part of preparation.

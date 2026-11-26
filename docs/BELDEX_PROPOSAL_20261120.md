# belnet-bridge: proposal to Beldex — 20 November 2026

**One line:** a first-hop HTTPS transport for BelNet that runs *on the BelNet
node itself*, survives content-based IWP filtering today, fails closed, and
comes with a reproducible evidence culture and a concrete plan for the
remaining DPI work.

---

## 1. What we are offering

### 1.1 The product

```text
BelNet client → local UDP adapter → TLS 1.3 / WSS :443 → first BelNet node
                                                          → its own IWP listener
                                                          → normal BelNet route
```

The bridge is not a separate anonymizing hop and not a generic VPN. The WSS
receiver lives **on the first BelNet node** and delivers only to that node's
own IWP socket. Consequences that matter to Beldex:

- **No extra infrastructure.** An entry operator runs one additional binary
  next to BelNet. No second server to fund, secure, or explain.
- **Minimal trust surface.** The server has a fixed destination (its own
  IWP listener); a working token buys transport to BelNet, not access to
  arbitrary hosts. Compare any generic tunnel, where a valid credential is
  also a public-IP gateway.
- **BelNet stays BelNet.** Encryption, identity, path selection and routing
  are untouched. The transport only changes how the first hop reaches the
  network — the component that censorship actually attacks.
- **Fails closed.** There is no raw-UDP fallback; if the transport or the
  trust check fails, traffic stops instead of leaking direct packets.

### 1.2 What is proven today (recorded, reproducible, audited)

Official, unmodified BelNet v0.9.8 in a private six-relay network with a
content-based IWP filter (keyed BLAKE2b verification of the 224-byte
introduction tag, independent of IP/port):

| Condition | Result |
| --- | --- |
| Direct BelNet through the filter | 0/3 requests — blocked |
| Same filter, first-hop HTTPS bridge | 10/10 steady requests, median 59.5 ms |
| Ordinary UDP and CA-verified HTTPS through the same filter | pass — no blanket block involved |

Every number is backed by saved manifests, binary hashes, classifier
decisions, eight packet captures per run, and an independent nonce audit.
`lab/run.sh` reproduces the whole experiment end to end.

### 1.3 What we deliberately report as open

- **IWP session continuity** across reconnects (native nodes retain the old
  client identity ~5 minutes; application recovery after a 30 s outage is
  currently 0/8 probes). The transport already retains UDP associations
  across WSS reconnects; closing the native side is integration engineering.
- **Adaptive DPI resistance.** A 15-round adaptive experiment (75 profile
  evaluations, 14 policy changes) did **not** achieve concealment: the final
  classifier detected 32/32 flows at 12/128 false positives. We ship this
  negative result with the evidence rather than hiding it, and Section 3 is
  the plan that follows from it.

---

## 2. The problems this solves for Beldex

1. **Entry censorship by content recognition.** The IWP introduction is
   recognizable on the wire; content filters can kill first connections
   without blocking UDP wholesale. The bridge removes that recognition
   surface today, on the official release binary.
2. **Entry blocking by address.** A bridge listener on 443 with a real
   certificate blends into ordinary web traffic far better than raw IWP.
   Private-ingress operation (reachable address not published as a
   RouterContact) is a configuration decision for Beldex, not a code change.
3. **Client integration cost.** No root, no TUN device, no second VPN
   service on Android. The client side is a small local adapter today and a
   native UDP hook inside the BelNet client as the reviewed next step — the
   right layer, already prototyped in the ecosystem.
4. **Credential operations.** Per-user tokens, quotas, and forced revocation
   of live sessions are specified for the integration phase (gaps we
   verified by auditing an independent alternative implementation).
5. **Credibility.** Beldex gets a transport whose claims are tied to frozen,
   hashed, reproducible evidence — including failures — which is exactly the
   posture a privacy network needs when a feature is marketed as
   censorship resistance.

---

## 3. Plan: closing the DPI gap

Goal, stated precisely: get the bridge **below the joint 5% false-positive
budget of an adaptive classical DPI** in our lab protocol (measured feature →
classical rule → transport change → fresh native runs → detector reply), then
hand the same frozen setup to an independent red team. We do not claim
mathematical indistinguishability from all internet traffic.

**Round 1 was instructive.** Combining the length header and payload into one
write removed the 24/26-byte TLS records, but the detector still caught all
fresh runs through its size/timing rules: one write does not control TCP
segment or TLS record boundaries. Lesson: shaping must happen at the record
and schedule layers, not the syscall layer.

**Stage A — kill the measured discriminators (weeks 1–4).**
- Enforce fixed-size TLS records (coalesce/split at the record layer) so size
  histograms lose the short-record modes.
- Bounded batching + pacing on both directions to break the reply-lag
  coupling (the round-2 detector rule) within a stated latency budget.
- Symmetric padding to common size buckets so upload/download volumes stop
  mirroring the request/response pattern.

**Stage B — look like the web (weeks 4–8).**
- Browser-grade ClientHello (uTLS Chrome profile, HTTP/2 ALPN) on the
  transport connection.
- A real cover site behind the entry listener: the WSS endpoint sits among
  genuine web content, with REALITY-style handshake where certificates are
  operator-managed. Our lab already maintains a mature REALITY baseline for
  exactly this comparison.
- Keep-alive and idle behavior matched to the cover stack.
- **B2 — connection-pool mimicry:** hold 2–4 parallel WSS connections to
  distinct entries and distribute streams across them with browser-like
  cadence, so the client never presents the "one eternal flow to one IP"
  signature that connection-level classifiers look for.

**Stage C — behave like the web (weeks 8–12).**
- Cell-based scheduling: fixed intervals, padding both directions, dummy
  traffic during silence — the v3 shaping machinery (cell sizes, bursts,
  polling, padding) already exists in the codebase and is waiting for
  parameter tuning against the detector, not new plumbing.
- Interleaved cover sessions so a blocked bridge does not go silent-dark.

**Stage D — independent verdict (weeks 12–14).**
- Re-run the 15-round adaptive protocol end to end with the joint 5% FPR
  budget on train/validation corpora that include real web traffic (our v2
  corpus already includes real Google/YouTube sessions).
- Ship the frozen setup, including all failures, to a reviewer outside the
  development loop — same discipline as the attached evidence bundle.

**Resilience extras (cheap, roadmap).**
- **Last-resort desync mode:** client-side packet-level evasion
  (fragmentation/TTL/segment tricks, the zapret family) for direct
  connections while fresh entry addresses are being distributed after an
  IP-block wave. No server needed; explicitly a stopgap, not the primary
  transport — it hides content, not destination IPs, and dies against
  fail-closed DPI.
- **Lab hardening:** run the desync trick catalogue against our own IWP
  detector to verify the reference censor is not blinded the same way
  production DPI is.

**Deliverables per stage:** source, frozen binaries and parameters, fresh
native runs with new identities and nonces, detector verdicts, and a short
ledger — the format of `docs/EVOLUTION.md`, which we commit to maintaining.

---

## 4. Why us / why now

We already built the lab, the detector, the audit tooling and the negative
results. The remaining work is engineering against a measured opponent, not
research in the dark. What we ask of Beldex: two engineers for interface
review (IWP admission, private ingress vs RouterContact publication, client
hook), a decision on packaging alongside BelNet, and a cooperating entry
operator for the final mainnet pilot. The engineering call is the right
place to start.

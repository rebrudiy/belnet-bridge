# Reply to Beldex Grants Program — 20 November 2026

Send-ready answer to Louis's 19-Nov request, now built as an offer: proven
first-hop transport + honest open items + a staged plan for the DPI work.
Attach `beldex-grant-20261120.tar.gz`. Supporting detail:
`docs/BELDEX_PROPOSAL_20261120.md`, `docs/PROOF.md`, `docs/THREAT_MODEL.md`,
`docs/INTEGRATION_PLAN.md`, `docs/EVOLUTION.md`. Reproduction:
`lab/README.md`.

---

Subject: Re: belnet-bridge — PoC, threat model, integration plan

Hello Louis,

Thank you for the technical review request. Bundle attached: recorded runs,
source snapshot, hashes, and the full proposal. Short version below.

## 1. Proof of concept

Real BelNet end to end: official, unmodified BelNet v0.9.8 in a private
six-relay network with a client and a `.bdx` HTTP service. The bridge is a
**first-hop HTTPS transport that runs on the BelNet node itself** — WSS
terminates on the first relay and delivers only to that relay's own IWP
listener. No separate forwarding host, no generic tunnel.

Recorded runs, 19 Nov 2026 UTC:

| Run | Condition | Startup | Steady HTTP | Median |
| --- | --- | --- | --- | --- |
| `20261119T025447Z-control` | Native UDP | 3 failures, 1 success | 10/10 | 51 ms |
| `20261119T025528Z-dpi` | Content-based IWP filter | 0/3 | — | — |
| `20261119T025556Z-dpi-tunnel` | Same filter + bridge | 1 failure, 1 success | 10/10 | 59.5 ms |

The filter verifies the 224-byte IWP introduction tag cryptographically; it
blocked direct BelNet while ordinary UDP and CA-verified HTTPS kept passing.
The HTTPS run was independently audited: 11/11 request nonces confirmed in
the service log, none in plaintext across eight captures; zero native
UDP/1090 on the wire. Reproduce everything with `lab/run.sh control|dpi|
dpi-tunnel` — the tunnel run includes the outage test by default. On the
engineering call I can also run the lab live and walk the team through a
fresh tunnel run end to end (~15 minutes).

**Disconnects, as asked:** zero established-session timeouts before the
outage; after a forced 30 s stop, WSS reconnected in 2 s but application
recovery was 0/8 and two established BelNet sessions timed out — a native
entry retains the old client identity for ~5 minutes. That continuity gap
is our first integration work item; the bridge side already survives WSS
reconnects.

## 2. Threat model

Full version attached. Summary: the client ISP sees IPs, ports, timing,
sizes and TLS fingerprints — but not the path, the token, or any payload
(TLS 1.3, verified certificates, no plaintext fallback). A disclosed
**address** enables scanning/IP blocking without enabling decryption;
address distribution and private ingress are a Beldex configuration
decision. A disclosed **token** lets whoever holds it *and* the address use
the tunnel; the control is rotation, and per-user tokens with forced
revocation of live sessions are on the integration roadmap. The entry
operator is trusted with metadata by design — the bridge does not weaken
BelNet's end-to-end protection.

We also ship a deliberately honest negative result: a 15-round adaptive DPI
experiment did not achieve concealment (final classifier 32/32 detections).
Detection and delivery are separate axes; we report both.

## 3. What we propose

**For BelNet:** integrate this as the first-hop transport option. It solves
entry censorship by content recognition today, needs no extra server, keeps
the client free of TUN/root/second-VPN complications, and fails closed.
The code is MIT-licensed and we are explicitly willing to have it packaged
alongside BelNet, with maintenance and support terms to be agreed — review
it in whatever form suits your process.

**The remaining work — beating adaptive DPI — is planned, not hand-waved:**
fixed TLS record sizes to remove the short-record signature, batching and
pacing against reply-lag rules, symmetric padding, browser-grade ClientHello
with a real cover site behind the listener, then cell-based scheduling with
dummy traffic — each stage validated against our adaptive detector under a
5% joint false-positive budget and, at the end, by an independent red team
on the frozen setup. Timeline and per-stage deliverables are in the
proposal; the engineering call is the right place to align it with your
maintainers' priorities.

I will book a slot through the Calendly link today.

Best regards,
[Author]

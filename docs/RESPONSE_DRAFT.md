# Beldex reply — unsent draft

19 November 2026. Technical results and the author's packaging position are populated. The engineering-call slot remains unselected. Nothing has been sent or booked.

---

Hello Louis,

Thank you for the technical review request.

The attached source and evidence package reproduces real BelNet v0.9.8 traffic to a `.bdx` service in an isolated private network. HTTPS terminates on the first BelNet relay itself, without a separate forwarding host.

The direct control delivered 10/10 steady requests (median 51 ms). A content-based IWP-introduction filter blocked direct BelNet (0/3 requests), while ordinary UDP and verified HTTPS remained available. With the same filter and first-hop HTTPS, BelNet delivered 10/10 steady requests (median 59.5 ms). Startup failures, classifier decisions, logs, captures and independent nonce checks are included.

The outage test exposed a limitation: after both listeners stopped for 30 seconds, WSS reconnected, but eight application recovery probes failed. Two established BelNet sessions timed out during the outage. IWP session continuity needs further work.

A separate adaptive experiment completed 15 retraining rounds and 75 live profile evaluations. It did not establish concealment: an independent final classifier detected 32/32 BelNet flows and marked 12/128 synthetic controls. Requests still succeeded 16/16; detection and denial are reported separately. This experiment uses a private TESTNET source build with a disclosed one-line scheduling patch, distinct from the official-release proof above.

V2 now retains the UDP association during WSS reconnects within running processes. Full process restart continuity remains open.

The package includes the threat model and integration proposal. These results demonstrate the stated private-lab scenario, not mainnet deployment or universal DPI resistance. I am willing to discuss packaging the code alongside BelNet, including maintenance and support arrangements.

An engineering-call slot is still to be confirmed.

Best regards,

[Author]

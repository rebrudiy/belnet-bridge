# Real introduction fixture

224-byte UDP payload from our own isolated BelNet v0.9.8 lab capture:
`lab/results/20261119T023559Z-control/client.pcap`.

- Flow: `10.88.0.20:56137 -> 10.88.0.12:1090` (entry2).
- Packet timestamp: Unix 1795055759.645559 (PCAP microseconds).
- Recipient public identity: `a50fbdeb18e40ca9db82b8d405eb4d70a92ea72b579fb13058398c7c80f26d5a`.
- Capture SHA-256: `774358f35d9a168f8d844ad753c951213d1209b472a07d5566fe385b255821e0`.
- Payload SHA-256: `2858b5a08bcdb99080a2897cbfa433024f057062aa578a3a8beb8a51b76c031f`.

Only the initial introduction is included. The identity is public RC field `k`;
no private keys or application data are needed to reproduce the tag verification.
The fixture was extracted and its tag checked independently with Python standard
library `hashlib.blake2b` before testing the Go implementation.

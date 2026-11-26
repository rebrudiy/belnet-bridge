# IWP introduction detector

Lab positive control for **known public relay identities** in BelNet v0.9.8.
It examines UDP payload bytes, without an IP/port blacklist or private keys.

The initial 224-byte introduction is `tag32 || nonce32 || ciphertext160`.
Let `K = BLAKE2b-256(RC["k"])`. A match requires the first 32 bytes to equal
keyed `BLAKE2b-256(nonce || ciphertext, key=K)`, using constant-time tag comparison.
This is keyed BLAKE2b, not the HMAC construction. No plaintext magic bytes exist.

Implementation sources: [initial public-key-derived key](https://github.com/Beldex-Coin/belnet/blob/v0.9.8/llarp/iwp/session.cpp#L35-L64),
[introduction and subsequent DH key change](https://github.com/Beldex-Coin/belnet/blob/v0.9.8/llarp/iwp/session.cpp#L437-L470),
[packet encryption/tag](https://github.com/Beldex-Coin/belnet/blob/v0.9.8/llarp/iwp/session.cpp#L154-L169),
[BLAKE2b implementations](https://github.com/Beldex-Coin/belnet/blob/v0.9.8/llarp/crypto/crypto_libsodium.cpp#L180-L193).

Use `ParseIdentity`, `New`, then `Match` on a complete, reassembled UDP payload.
The caller handles IP parsing, fragmentation and forwarding/drop decisions.
The detector is immutable and supports concurrent calls.

This recognizes initial introductions to known identities, including compatible
IWP implementations. It misses unknown identities and established DH sessions.
Anyone knowing the public identity can construct a matching tag. WSS encrypts
these bytes inside TLS, so this exact test cannot inspect the inner introduction.
Passing this lab control does not establish resistance to other DPI classifiers.

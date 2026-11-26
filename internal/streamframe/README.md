# Stream framing for a mature transport adapter

This package only frames datagrams inside an already established byte stream.
The caller provides TLS/REALITY or another secure transport, validates the token,
owns timeouts, and attaches the authenticated session to its fixed UDP target.
No goroutines, scheduling, reconnect logic, target selection or session store live here.

Handshake: `BDG1 | SID[32] | token_length uint16 BE | token[1..1024 bytes]`.
The all-zero SID is invalid. The server sends exactly `BDGA` only after the caller
has authenticated and attached the session. This acknowledgement does not confirm
that any later UDP packet reached BelNet.

Datagram: `length uint32 BE | payload[0..65507 bytes]`. An empty datagram is
represented explicitly and differs from EOF. Lengths are checked before payload
allocation; write-side validation happens before writing a header. Partial writes
are completed, but a zero-progress writer fails with `io.ErrShortWrite`.

Use one reader and one serialized writer per stream. Reader and writer may run
concurrently in the caller if the underlying stream supports full duplex.
After any framing/I/O error, discard the stream. An interrupted frame is not
resynchronized or replayed. A successful write is not a delivery ACK; reconnect
can lose datagrams or leave delivery uncertain. Session retention and retry policy
belong to the adapter, outside this codec.

Errors do not print tokens or arbitrary underlying I/O text. `errors.Is` and
`errors.As` still expose the original I/O cause; callers should not log unwrapped
errors from untrusted I/O implementations without reviewing their contents.
The package keeps no credential cache or session state. It does not promise
zeroization of temporary Go allocations.

Run `go test -race ./internal/streamframe` and `go vet ./internal/streamframe`.

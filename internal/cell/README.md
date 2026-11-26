# V3 cells

This package carries UDP datagrams inside equal-size application messages. It
provides framing and padding; the transport supplies authentication, encryption,
request/reply pacing and reconnects. It does not establish DPI evasion.

## Data path

```text
UDP payload → Encoder.Push → Next(cell size) → encrypted transport
UDP payload ← Decoder.Accept              ← decrypted cell
```

`Next` returns exactly 256–8192 bytes. One cell contains one fragment, or a dummy
when the queue is empty. The request and reply encoders should use the same size.
Useful bytes per cell are `size - 20`; a 1024-byte cell carries at most 1004 bytes.
For example, 60,000 bytes need 60 cells at that size. Cadence determines throughput
and delay; no size or padding multiplier guarantees an acceptable connection.

`Push` copies its input. `Accept` returns owned output buffers and preserves UDP
datagram boundaries and order. Empty UDP datagrams are data cells and are distinct
from dummies. Datagrams can be 0–65,507 bytes. Fragments cannot be interleaved.

## Wire format

All integers use big-endian byte order. A cell has this 20-byte header, followed
by the fragment and cryptographically random padding:

| Bytes | Field |
|---|---|
| 0 | Version: 3 |
| 1 | Kind: 0 dummy, 1 data |
| 2 | Flags: bit 0 start, bit 1 end |
| 3 | Reserved: 0 |
| 4–7 | Nonzero datagram ID |
| 8–11 | Total datagram bytes |
| 12–15 | Fragment offset |
| 16–17 | Fragment bytes in this cell |
| 18–19 | Reserved: 0 |

Dummy headers have all fields except version set to zero. IDs advance by one,
wrapping from `2^32-1` to 1. The first ID in a connection epoch may be arbitrary.
The decoder rejects invalid sizes, flags, IDs, overlaps, gaps, replayed starts,
unknown continuations and changes to the total length before copying data.

## Bounds and lifecycle

- Encoder: at most 64 queued datagrams and 1 MiB of queued payload allocation.
  `ErrQueueFull` rejects input without evicting earlier packets.
- Decoder: one incomplete datagram, at most 65,507 bytes. Its lifetime is 10
  seconds from the first fragment. `Accept` checks expiration; call `Expire` on
  the transport timer if cells stop arriving. There are no background goroutines.
- `Close` rejects new input, allows the queued data to drain, then `Next` returns
  `ErrDrained`. `Abort` immediately discards queued data and closes the encoder.
- On reconnect, reset the peer decoder and call `Rewind` on the sender encoder
  at the same epoch boundary. This restarts the partially encoded head datagram.
  Serialize this transition with the sending loop.
- A successful `Next` consumes a fragment before the network write. A failed
  write can lose a complete datagram; a partial datagram is never delivered.
  `Rewind` cannot recover a fully consumed datagram. There are no delivery ACKs,
  retransmission or exactly-once guarantees. Close a stream on decoding errors.

All public operations are mutex protected. The caller owns scheduling and context
cancellation. Do not reuse a decoder across uncoordinated connection epochs.

`Snapshot` exposes payload, padding, dummy and queue counters, plus maximum queue
wait and datagram age. Encoder completion counts encoding, not delivery. Decoder
completion counts successful reassembly, not delivery to the destination socket.

Validation: `go test -race ./internal/cell` and `go vet ./internal/cell`.

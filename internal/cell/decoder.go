package cell

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type DecoderStats struct {
	InputCells         uint64 `json:"input_cells"`
	InputBytes         uint64 `json:"input_bytes"`
	DummyCells         uint64 `json:"dummy_cells"`
	CompletedDatagrams uint64 `json:"completed_datagrams"`
	CompletedBytes     uint64 `json:"completed_bytes"`
	RejectedCells      uint64 `json:"rejected_cells"`
	ExpiredDatagrams   uint64 `json:"expired_datagrams"`
	ResetDatagrams     uint64 `json:"reset_datagrams"`
	PendingDatagrams   int    `json:"pending_datagrams"`
	PendingBytes       int    `json:"pending_bytes"`
	MaxPendingBytes    int    `json:"max_pending_bytes"`
}

type assembly struct {
	id      uint32
	data    []byte
	offset  int
	started time.Time
}

// Decoder accepts ordered, non-interleaved fragments, as emitted by Encoder.
// At most one datagram (at most 65,507 bytes) is allocated for reassembly, well
// below MaxPendingBytes. A peer cannot allocate an unbounded map of fragment IDs.
// Use one decoder per connection epoch and Reset when replacing the connection.
// Authentication is the caller's responsibility.
type Decoder struct {
	mu      sync.Mutex
	clock   func() time.Time
	pending *assembly
	lastID  uint32
	seenID  bool
	stats   DecoderStats
}

func NewDecoder() *Decoder { return &Decoder{clock: time.Now} }

// Accept returns complete UDP payloads. A dummy or partial fragment returns an
// empty result. A genuine empty datagram returns a single non-nil zero-byte slice.
// Errors do not expose partially assembled data; callers should close a
// malformed stream rather than silently interpreting it as a successful bypass.
func (d *Decoder) Accept(frame []byte) (packets [][]byte, returnedErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if returnedErr != nil {
			d.stats.RejectedCells++
		}
	}()
	now := d.clock()
	d.expire(now)
	if !ValidSize(len(frame)) || frame[0] != Version || frame[3] != 0 || frame[18] != 0 || frame[19] != 0 {
		return nil, ErrMalformed
	}
	kind, flags := frame[1], frame[2]
	id := binary.BigEndian.Uint32(frame[4:8])
	total := int(binary.BigEndian.Uint32(frame[8:12]))
	offset := int(binary.BigEndian.Uint32(frame[12:16]))
	size := int(binary.BigEndian.Uint16(frame[16:18]))
	if kind == kindDummy {
		if flags != 0 || id != 0 || total != 0 || offset != 0 || size != 0 {
			return nil, ErrMalformed
		}
		d.stats.InputCells++
		d.stats.InputBytes += uint64(len(frame))
		d.stats.DummyCells++
		return nil, nil
	}
	if kind != kindData || flags&^(flagStart|flagEnd) != 0 || id == 0 || total > MaxDatagram || offset > total || size > len(frame)-HeaderSize || size > total-offset {
		return nil, ErrMalformed
	}
	start, end := flags&flagStart != 0, flags&flagEnd != 0
	if start != (offset == 0) || end != (offset+size == total) || (size == 0 && total != 0) {
		return nil, ErrMalformed
	}
	if start {
		if d.pending != nil || (d.seenID && id != followingID(d.lastID)) {
			return nil, ErrSequence
		}
		// All headers and allocation sizes have been checked before allocation.
		d.pending = &assembly{id: id, data: make([]byte, total), started: now}
		d.lastID, d.seenID = id, true
		d.stats.MaxPendingBytes = max(d.stats.MaxPendingBytes, total)
	} else if d.pending == nil || id != d.pending.id || total != len(d.pending.data) || offset != d.pending.offset {
		return nil, ErrSequence
	}
	packet := d.pending
	copy(packet.data[offset:offset+size], frame[HeaderSize:HeaderSize+size])
	packet.offset += size
	d.stats.InputCells++
	d.stats.InputBytes += uint64(len(frame))
	if !end {
		return nil, nil
	}
	d.pending = nil
	d.stats.CompletedDatagrams++
	d.stats.CompletedBytes += uint64(total)
	return [][]byte{packet.data}, nil
}

// Expire applies the bounded reassembly lifetime even when no cells arrive.
// It reports whether an incomplete datagram was discarded. Callers may invoke it
// on their own timer; Accept also checks the deadline before processing a cell.
func (d *Decoder) Expire() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expire(d.clock())
}

func (d *Decoder) expire(now time.Time) bool {
	if d.pending != nil && now.Sub(d.pending.started) >= ReassemblyTimeout {
		d.pending = nil
		d.stats.ExpiredDatagrams++
		return true
	}
	return false
}

// Reset starts a new connection epoch and discards any incomplete datagram.
// The next start ID can be arbitrary (nonzero); it is then sequentially checked.
func (d *Decoder) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending != nil {
		d.stats.ResetDatagrams++
	}
	d.pending = nil
	d.lastID, d.seenID = 0, false
}

func (d *Decoder) Snapshot() DecoderStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	stats := d.stats
	if d.pending != nil {
		stats.PendingDatagrams = 1
		stats.PendingBytes = len(d.pending.data)
	}
	return stats
}

func (s DecoderStats) String() string {
	return fmt.Sprintf("cells=%d completed=%d pending=%d rejected=%d", s.InputCells, s.CompletedDatagrams, s.PendingDatagrams, s.RejectedCells)
}

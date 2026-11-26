// Package cell provides bounded, ordered UDP fragmentation into padded v3 cells.
// It does not authenticate connections, provide retransmission, schedule traffic,
// or make a cell stream indistinguishable from ordinary HTTPS.
package cell

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	Version           = 3
	HeaderSize        = 20
	MinSize           = 256
	MaxSize           = 8192
	MaxDatagram       = 65507
	MaxPending        = 64
	MaxPendingBytes   = 1024 * 1024
	ReassemblyTimeout = 10 * time.Second

	kindDummy = 0
	kindData  = 1
	flagStart = 1
	flagEnd   = 2
)

var (
	ErrQueueFull = errors.New("cell datagram queue is full")
	ErrClosed    = errors.New("cell encoder is closed")
	ErrDrained   = errors.New("cell encoder is closed and drained")
	ErrMalformed = errors.New("malformed cell")
	ErrSequence  = errors.New("unexpected cell fragment sequence")
)

// Stats counts accepted data and successful cell encodings, not delivery ACKs.
// Queue bytes retain the complete allocation until the datagram is finished.
// MaxQueueWaitMicros ends at the first fragment; MaxDatagramAgeMicros also
// includes the time spent fragmenting the datagram across subsequent cells.
type Stats struct {
	InputDatagrams       uint64 `json:"input_datagrams"`
	InputBytes           uint64 `json:"input_bytes"`
	CompletedDatagrams   uint64 `json:"completed_datagrams"`
	OutputCells          uint64 `json:"output_cells"`
	OutputBytes          uint64 `json:"output_bytes"`
	PayloadBytes         uint64 `json:"payload_bytes"`
	PaddingBytes         uint64 `json:"padding_bytes"`
	DummyCells           uint64 `json:"dummy_cells"`
	RejectedDatagrams    uint64 `json:"rejected_datagrams"`
	AbortedDatagrams     uint64 `json:"aborted_datagrams"`
	Rewinds              uint64 `json:"rewinds"`
	QueueDatagrams       int    `json:"queue_datagrams"`
	QueueBytes           int    `json:"queue_bytes"`
	MaxQueueDatagrams    int    `json:"max_queue_datagrams"`
	MaxQueueBytes        int    `json:"max_queue_bytes"`
	MaxQueueWaitMicros   uint64 `json:"max_queue_wait_micros"`
	MaxDatagramAgeMicros uint64 `json:"max_datagram_age_micros"`
}

type datagram struct {
	id      uint32
	data    []byte
	offset  int
	arrived time.Time
}

// Encoder may be shared by one producer and one sender (or other concurrent
// callers). Push copies its input. Cells and returned datagrams own their bytes.
// There are no background goroutines. Callers choose pacing and cancellation.
type Encoder struct {
	mu     sync.Mutex
	random io.Reader
	clock  func() time.Time
	queue  []datagram
	bytes  int
	nextID uint32
	closed bool
	stats  Stats
}

// NewEncoder uses cryptographic randomness by default. A non-nil random source
// is intended for deterministic tests; it must not be used for live camouflage.
func NewEncoder(random io.Reader) *Encoder {
	if random == nil {
		random = rand.Reader
	}
	return &Encoder{random: random, clock: time.Now, nextID: 1}
}

func ValidSize(size int) bool { return size >= MinSize && size <= MaxSize }

// Push accepts a complete UDP payload, including a genuine empty datagram.
// Queue overflow returns ErrQueueFull rather than evicting an earlier datagram.
func (e *Encoder) Push(packet []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		e.stats.RejectedDatagrams++
		return ErrClosed
	}
	if len(packet) > MaxDatagram {
		e.stats.RejectedDatagrams++
		return fmt.Errorf("datagram exceeds %d bytes", MaxDatagram)
	}
	if len(e.queue) >= MaxPending || e.bytes+len(packet) > MaxPendingBytes {
		e.stats.RejectedDatagrams++
		return ErrQueueFull
	}
	copyOfPacket := make([]byte, len(packet))
	copy(copyOfPacket, packet)
	e.queue = append(e.queue, datagram{e.nextID, copyOfPacket, 0, e.clock()})
	e.nextID = followingID(e.nextID)
	e.bytes += len(packet)
	e.stats.InputDatagrams++
	e.stats.InputBytes += uint64(len(packet))
	e.stats.MaxQueueDatagrams = max(e.stats.MaxQueueDatagrams, len(e.queue))
	e.stats.MaxQueueBytes = max(e.stats.MaxQueueBytes, e.bytes)
	return nil
}

// Next returns exactly size bytes, containing one fragment or a dummy. Open
// empty encoders emit dummies. Close permits draining, then returns ErrDrained.
// A successful call consumes the fragment BEFORE the caller writes it to a
// connection: there is no delivery ACK and a failed write can lose a datagram.
// Random-source or size errors leave queued data untouched.
func (e *Encoder) Next(size int) ([]byte, error) {
	if !ValidSize(size) {
		return nil, fmt.Errorf("cell size must be %d..%d bytes", MinSize, MaxSize)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed && len(e.queue) == 0 {
		return nil, ErrDrained
	}
	frame := make([]byte, size)
	// Fill first, before changing queue state, so randomness failure is atomic.
	if _, err := io.ReadFull(e.random, frame[HeaderSize:]); err != nil {
		return nil, fmt.Errorf("cell padding randomness: %w", err)
	}
	frame[0] = Version
	payload := 0
	if len(e.queue) == 0 {
		frame[1] = kindDummy
		e.stats.DummyCells++
	} else {
		packet := &e.queue[0]
		payload = min(size-HeaderSize, len(packet.data)-packet.offset)
		end := packet.offset + payload
		frame[1] = kindData
		if packet.offset == 0 {
			frame[2] |= flagStart
			e.stats.MaxQueueWaitMicros = max(e.stats.MaxQueueWaitMicros, ageMicros(e.clock(), packet.arrived))
		}
		if end == len(packet.data) {
			frame[2] |= flagEnd
		}
		binary.BigEndian.PutUint32(frame[4:8], packet.id)
		binary.BigEndian.PutUint32(frame[8:12], uint32(len(packet.data)))
		binary.BigEndian.PutUint32(frame[12:16], uint32(packet.offset))
		binary.BigEndian.PutUint16(frame[16:18], uint16(payload))
		copy(frame[HeaderSize:HeaderSize+payload], packet.data[packet.offset:end])
		packet.offset = end
		e.stats.MaxDatagramAgeMicros = max(e.stats.MaxDatagramAgeMicros, ageMicros(e.clock(), packet.arrived))
		if end == len(packet.data) {
			e.bytes -= len(packet.data)
			e.stats.CompletedDatagrams++
			copy(e.queue, e.queue[1:])
			e.queue[len(e.queue)-1] = datagram{}
			e.queue = e.queue[:len(e.queue)-1]
		}
	}
	e.stats.OutputCells++
	e.stats.OutputBytes += uint64(size)
	e.stats.PayloadBytes += uint64(payload)
	e.stats.PaddingBytes += uint64(size - HeaderSize - payload)
	return frame, nil
}

// Close rejects new Push calls. Queued datagrams remain available through Next.
// No dummy is emitted after the closed queue drains.
func (e *Encoder) Close() { e.mu.Lock(); e.closed = true; e.mu.Unlock() }

// Abort is the immediate-cancellation operation: discard pending datagrams and
// reject future input. A cell already returned by Next cannot be retracted.
func (e *Encoder) Abort() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.stats.AbortedDatagrams += uint64(len(e.queue))
	e.queue = nil
	e.bytes = 0
}

// Rewind restarts an incompletely encoded head datagram for a new connection.
// The peer MUST Reset its Decoder at the same epoch boundary. Fully consumed
// datagrams cannot be recovered: this is not reliable or exactly-once delivery.
func (e *Encoder) Rewind() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.queue) != 0 && e.queue[0].offset > 0 {
		e.queue[0].offset = 0
		e.stats.Rewinds++
	}
}

func (e *Encoder) Snapshot() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	stats := e.stats
	stats.QueueDatagrams = len(e.queue)
	stats.QueueBytes = e.bytes
	return stats
}

func followingID(id uint32) uint32 {
	id++
	if id == 0 {
		return 1
	}
	return id
}

func ageMicros(now, then time.Time) uint64 {
	if now.Before(then) {
		return 0
	}
	return uint64(now.Sub(then).Microseconds())
}

package shaping

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

const (
	frameVersion = 2
	frameHeader  = 3
)

// Encode makes one versioned envelope: version, count, length-prefixed datagrams,
// then padding. A zero count is a dummy; a zero-length datagram remains data.
// A nil random source uses crypto/rand. Injected readers are for tests/lab runs.
func Encode(datagrams [][]byte, p Policy, random io.Reader) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(datagrams) > MaxBatch {
		return nil, fmt.Errorf("too many datagrams: %d", len(datagrams))
	}
	if random == nil {
		random = rand.Reader
	}
	base := frameHeader
	for _, packet := range datagrams {
		if len(packet) > MaxDatagram {
			return nil, fmt.Errorf("datagram exceeds %d bytes", MaxDatagram)
		}
		base += 2 + len(packet)
	}
	if base > MaxFrame {
		return nil, fmt.Errorf("datagram batch exceeds %d bytes", MaxFrame)
	}
	target := base
	if len(datagrams) == 0 {
		target = max(target, p.DummyBytes)
	}
	if p.PadTo > 0 {
		target = ((target + p.PadTo - 1) / p.PadTo) * p.PadTo
	}
	jitter, err := randomBelow(random, p.PadJitter+1)
	if err != nil {
		return nil, err
	}
	target = min(MaxFrame, target+jitter)
	frame := make([]byte, target)
	frame[0] = frameVersion
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(datagrams)))
	offset := frameHeader
	for _, packet := range datagrams {
		binary.BigEndian.PutUint16(frame[offset:offset+2], uint16(len(packet)))
		offset += 2
		copy(frame[offset:], packet)
		offset += len(packet)
	}
	if _, err := io.ReadFull(random, frame[offset:]); err != nil {
		return nil, fmt.Errorf("padding randomness: %w", err)
	}
	return frame, nil
}

// Decode does not need the sender's policy. Returned packets own their memory.
func Decode(frame []byte) ([][]byte, error) {
	if len(frame) < frameHeader || len(frame) > MaxFrame || frame[0] != frameVersion {
		return nil, fmt.Errorf("invalid shaping frame")
	}
	count := int(binary.BigEndian.Uint16(frame[1:3]))
	if count > MaxBatch {
		return nil, fmt.Errorf("datagram count exceeds %d", MaxBatch)
	}
	packets := make([][]byte, 0, count)
	offset := frameHeader
	for range count {
		if len(frame)-offset < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		size := int(binary.BigEndian.Uint16(frame[offset : offset+2]))
		offset += 2
		if size > MaxDatagram || size > len(frame)-offset {
			return nil, fmt.Errorf("invalid datagram length %d", size)
		}
		packet := make([]byte, size)
		copy(packet, frame[offset:offset+size])
		packets = append(packets, packet)
		offset += size
	}
	return packets, nil
}

func randomBelow(random io.Reader, limit int) (int, error) {
	if limit <= 1 {
		return 0, nil
	}
	n, err := rand.Int(random, big.NewInt(int64(limit)))
	if err != nil {
		return 0, fmt.Errorf("shaping randomness: %w", err)
	}
	return int(n.Int64()), nil
}

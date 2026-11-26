package shaping

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

type Stats struct {
	InputDatagrams      uint64 `json:"input_datagrams"`
	InputBytes          uint64 `json:"input_bytes"`
	OutputFrames        uint64 `json:"output_frames"`
	OutputBytes         uint64 `json:"output_bytes"`
	DummyFrames         uint64 `json:"dummy_frames"`
	PaddingBytes        uint64 `json:"padding_bytes"`
	MaxQueueDatagrams   uint64 `json:"max_queue_datagrams"`
	MaxQueueBytes       uint64 `json:"max_queue_bytes"`
	MaxQueueDelayMicros uint64 `json:"max_queue_delay_micros"`
}

// Sender is single-use. Snapshot may run concurrently with Run.
type Sender struct {
	policy                                                Policy
	random                                                io.Reader
	started                                               atomic.Bool
	inputDatagrams, inputBytes, outputFrames, outputBytes atomic.Uint64
	dummyFrames, paddingBytes                             atomic.Uint64
	maxQueueDatagrams, maxQueueBytes, maxQueueDelayMicros atomic.Uint64
}

func NewSender(p Policy, random io.Reader) (*Sender, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	return &Sender{policy: p, random: random}, nil
}

func (s *Sender) Snapshot() Stats {
	return Stats{
		InputDatagrams: s.inputDatagrams.Load(), InputBytes: s.inputBytes.Load(),
		OutputFrames: s.outputFrames.Load(), OutputBytes: s.outputBytes.Load(),
		DummyFrames: s.dummyFrames.Load(), PaddingBytes: s.paddingBytes.Load(),
		MaxQueueDatagrams: s.maxQueueDatagrams.Load(), MaxQueueBytes: s.maxQueueBytes.Load(),
		MaxQueueDelayMicros: s.maxQueueDelayMicros.Load(),
	}
}

type queuedPacket struct {
	data    []byte
	arrival time.Time
}

// Run owns packets received from in: producers must not mutate them afterwards.
// It preserves order and datagram boundaries and backpressures a full queue.
// The 100 ms scheduler deadline excludes time blocked in emit; emit must honor ctx.
// QueueDelay statistics include that backpressure, rather than hiding it.
// Closing in flushes queued data and stops dummies. Cancellation stops immediately.
func (s *Sender) Run(ctx context.Context, in <-chan []byte, emit func(context.Context, []byte) error) error {
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("sender is single-use")
	}
	if emit == nil {
		return fmt.Errorf("emit callback is required")
	}
	p := s.policy
	pending := make([]queuedPacket, 0, MaxQueue)
	queueBytes, warmup := 0, p.WarmupFrames
	var realBytes, dummySpent uint64
	var nextSend time.Time
	nextDummy := time.Now()
	if warmup == 0 {
		nextDummy = nextDummy.Add(time.Duration(p.DummyIntervalMS) * time.Millisecond)
	}
	closed := false
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	accept := func(packet []byte) error {
		if len(packet) > MaxDatagram {
			return fmt.Errorf("datagram exceeds %d bytes", MaxDatagram)
		}
		pending = append(pending, queuedPacket{packet, time.Now()})
		queueBytes += len(packet)
		realBytes += uint64(len(packet))
		s.inputDatagrams.Add(1)
		s.inputBytes.Add(uint64(len(packet)))
		updateMax(&s.maxQueueDatagrams, uint64(len(pending)))
		updateMax(&s.maxQueueBytes, uint64(queueBytes))
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if closed && len(pending) == 0 {
			return nil
		}
		var input <-chan []byte
		if !closed && len(pending) < MaxQueue && queueBytes <= MaxQueueBytes-MaxDatagram {
			input = in
		}
		// Consume available packets before deciding whether batching is worthwhile.
		if input != nil {
			select {
			case packet, ok := <-input:
				if !ok {
					closed = true
				} else if err := accept(packet); err != nil {
					return err
				}
				continue
			default:
			}
		}
		var realDue time.Time
		if len(pending) > 0 {
			realDue = pending[0].arrival.Add(time.Duration(p.BatchDelayMS) * time.Millisecond)
			if len(pending) >= p.batchMax() {
				realDue = pending[0].arrival
			}
			if nextSend.After(realDue) {
				realDue = nextSend
			}
			deadline := pending[0].arrival.Add(MaxDelayMS * time.Millisecond)
			if realDue.After(deadline) {
				realDue = deadline
			}
		}
		var dummyDue time.Time
		if !closed && (warmup > 0 || p.DummyIntervalMS > 0) && dummySpent+uint64(dummyMaximum(p)) <= InitialDummyCredit+realBytes/2 {
			dummyDue = nextDummy
			if nextSend.After(dummyDue) {
				dummyDue = nextSend
			}
			// A dummy must not consume the real packet's remaining pacing budget.
			if !realDue.IsZero() && !dummyDue.Add(time.Duration(p.PaceMinMS+p.PaceJitterMS)*time.Millisecond).Before(realDue) {
				dummyDue = time.Time{}
			}
		}
		due, isDummy := realDue, false
		if !dummyDue.IsZero() && (due.IsZero() || dummyDue.Before(due)) {
			due, isDummy = dummyDue, true
		}
		var wake <-chan time.Time
		if !due.IsZero() {
			timer.Reset(max(time.Until(due), 0))
			wake = timer.C
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet, ok := <-input:
			if !ok {
				closed = true
			} else if err := accept(packet); err != nil {
				return err
			}
		case <-wake:
			var packets [][]byte
			payloadBytes := 0
			if !isDummy {
				frameBytes := frameHeader
				for _, packet := range pending {
					if len(packets) >= p.batchMax() || frameBytes+2+len(packet.data) > MaxFrame {
						break
					}
					packets = append(packets, packet.data)
					frameBytes += 2 + len(packet.data)
					payloadBytes += len(packet.data)
					updateMax(&s.maxQueueDelayMicros, uint64(max(time.Since(packet.arrival).Microseconds(), 0)))
				}
			}
			frame, err := Encode(packets, p, s.random)
			if err != nil {
				return err
			}
			if err := emit(ctx, frame); err != nil {
				return err
			}
			s.outputFrames.Add(1)
			s.outputBytes.Add(uint64(len(frame)))
			s.paddingBytes.Add(uint64(len(frame) - frameHeader - 2*len(packets) - payloadBytes))
			if isDummy {
				dummySpent += uint64(len(frame))
				s.dummyFrames.Add(1)
				if warmup > 0 {
					warmup--
				}
				nextDummy = time.Now()
				if warmup == 0 {
					nextDummy = nextDummy.Add(time.Duration(p.DummyIntervalMS) * time.Millisecond)
				}
			} else {
				queueBytes -= payloadBytes
				copy(pending, pending[len(packets):])
				for i := len(pending) - len(packets); i < len(pending); i++ {
					pending[i] = queuedPacket{}
				}
				pending = pending[:len(pending)-len(packets)]
			}
			jitter, err := randomBelow(s.random, p.PaceJitterMS+1)
			if err != nil {
				return err
			}
			nextSend = time.Now().Add(time.Duration(p.PaceMinMS+jitter) * time.Millisecond)
		}
		if !timer.Stop() && wake != nil {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func dummyMaximum(p Policy) int {
	size := max(frameHeader, p.DummyBytes)
	if p.PadTo > 0 {
		size = ((size + p.PadTo - 1) / p.PadTo) * p.PadTo
	}
	return min(MaxFrame, size+p.PadJitter)
}

func updateMax(value *atomic.Uint64, next uint64) {
	for current := value.Load(); next > current; current = value.Load() {
		if value.CompareAndSwap(current, next) {
			return
		}
	}
}

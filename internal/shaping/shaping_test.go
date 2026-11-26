package shaping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func TestCodecPreservesDatagramsAndSeparatesDummies(t *testing.T) {
	for _, packets := range [][][]byte{
		nil,
		{[]byte{}},
		{[]byte("one"), {}, []byte("three")},
		{bytes.Repeat([]byte{0xa7}, MaxDatagram), bytes.Repeat([]byte{0x31}, MaxDatagram)},
	} {
		for _, policy := range []Policy{{}, {PadTo: 256}, {PadTo: 4096, PadJitter: 4096}} {
			frame, err := Encode(packets, policy, rand.New(rand.NewSource(73)))
			if err != nil {
				t.Fatal(err)
			}
			if len(frame) > MaxFrame {
				t.Fatal("frame exceeded read limit")
			}
			decoded, err := Decode(frame)
			if err != nil || len(decoded) != len(packets) {
				t.Fatalf("count mismatch: %v", err)
			}
			for i := range packets {
				if !bytes.Equal(decoded[i], packets[i]) {
					t.Fatal("datagram content changed")
				}
			}
			// Decoding must not retain aliases to the websocket's receive buffer.
			for i := range frame {
				frame[i] = 0
			}
			for i := range packets {
				if !bytes.Equal(decoded[i], packets[i]) {
					t.Fatal("decoded datagram aliases frame")
				}
			}
		}
	}
}

func TestCodecRejectsMalformedAndOversizedData(t *testing.T) {
	for _, frame := range [][]byte{
		nil, {2}, {2, 0}, {1, 0, 0}, {2, 0, MaxBatch + 1},
		{2, 0, 1}, {2, 0, 1, 0}, {2, 0, 1, 0, 2, 1},
		append([]byte{2, 0, 0}, make([]byte, MaxFrame)...),
	} {
		if _, err := Decode(frame); err == nil {
			t.Fatalf("accepted malformed frame with %d bytes", len(frame))
		}
	}
	bad := make([]byte, 5+MaxDatagram+1)
	bad[0] = frameVersion
	binary.BigEndian.PutUint16(bad[1:3], 1)
	binary.BigEndian.PutUint16(bad[3:5], MaxDatagram+1)
	if _, err := Decode(bad); err == nil {
		t.Fatal("accepted oversized UDP payload")
	}
	for _, packets := range [][][]byte{
		make([][]byte, MaxBatch+1),
		{make([]byte, MaxDatagram+1)},
		{make([]byte, MaxDatagram), make([]byte, MaxDatagram), make([]byte, MaxDatagram)},
	} {
		if _, err := Encode(packets, Policy{}, nil); err == nil {
			t.Fatal("accepted oversized batch")
		}
	}
}

func TestPolicyRejectsUnboundedWork(t *testing.T) {
	for _, policy := range []Policy{
		{PadTo: -1}, {PadTo: 4097}, {PadJitter: -1}, {PadJitter: 4097},
		{BatchMax: -1}, {BatchMax: MaxBatch + 1},
		{BatchDelayMS: -1}, {BatchDelayMS: 101},
		{PaceMinMS: -1}, {PaceMinMS: 101}, {PaceMinMS: 80, PaceJitterMS: 21},
		{DummyIntervalMS: 1}, {DummyIntervalMS: -1}, {DummyIntervalMS: 60001},
		{DummyBytes: -1}, {DummyBytes: 4097}, {WarmupFrames: -1}, {WarmupFrames: 9},
	} {
		if _, err := NewSender(policy, nil); err == nil {
			t.Fatalf("accepted policy %+v", policy)
		}
	}
	if err := (Profile{Name: "experiment", Up: Policy{PadTo: 256}, Down: Policy{WarmupFrames: 1}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRandomnessFailureIsAnError(t *testing.T) {
	if _, err := Encode([][]byte{[]byte("packet")}, Policy{PadTo: 64}, failedReader{}); err == nil {
		t.Fatal("ignored failed randomness")
	}
}

func TestSenderFlushesBatchesInOrderWithExactStats(t *testing.T) {
	input := make(chan []byte, 40)
	want := make([][]byte, 0, cap(input))
	var inputBytes uint64
	for i := range cap(input) {
		packet := bytes.Repeat([]byte{byte(i)}, i*7)
		if i == 2 || i == 3 {
			packet = bytes.Repeat([]byte{byte(i)}, MaxDatagram)
		}
		input <- packet
		want = append(want, packet)
		inputBytes += uint64(len(packet))
	}
	close(input)
	sender, err := NewSender(Policy{BatchMax: 16, PadTo: 256, PadJitter: 11}, rand.New(rand.NewSource(92)))
	if err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	var frameBytes, paddingBytes, frames uint64
	err = sender.Run(context.Background(), input, func(_ context.Context, frame []byte) error {
		packets, err := Decode(frame)
		if err != nil {
			return err
		}
		got = append(got, packets...)
		frameBytes += uint64(len(frame))
		frames++
		base := frameHeader + 2*len(packets)
		for _, packet := range packets {
			base += len(packet)
		}
		paddingBytes += uint64(len(frame) - base)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("batching lost, reordered, or altered datagrams")
	}
	stats := sender.Snapshot()
	if stats.InputDatagrams != uint64(len(want)) || stats.InputBytes != inputBytes || stats.OutputFrames != frames || stats.OutputBytes != frameBytes || stats.PaddingBytes != paddingBytes || stats.DummyFrames != 0 {
		t.Fatalf("incorrect accounting: %+v", stats)
	}
	if stats.MaxQueueDatagrams > MaxQueue || stats.MaxQueueBytes > MaxQueueBytes {
		t.Fatal("queue bounds exceeded")
	}
}

func TestSenderQueueBackpressureDoesNotDropPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	input := make(chan []byte)
	go func() {
		defer close(input)
		for i := range 70 {
			packet := bytes.Repeat([]byte{byte(i)}, MaxDatagram)
			select {
			case input <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	sender, _ := NewSender(Policy{PaceMinMS: 1}, nil)
	count := 0
	err := sender.Run(ctx, input, func(_ context.Context, frame []byte) error {
		packets, err := Decode(frame)
		if err != nil {
			return err
		}
		if len(packets) != 1 || len(packets[0]) != MaxDatagram || packets[0][0] != byte(count) {
			t.Error("datagram order or content changed")
		}
		count++
		return nil
	})
	if err != nil || count != 70 {
		t.Fatalf("packets lost: got %d, error %v", count, err)
	}
	stats := sender.Snapshot()
	if stats.MaxQueueDatagrams > MaxQueue || stats.MaxQueueBytes > MaxQueueBytes {
		t.Fatalf("unbounded buffering: %+v", stats)
	}
}

func TestSenderDummyBudgetAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	sender, _ := NewSender(Policy{DummyIntervalMS: 10, DummyBytes: 4096, WarmupFrames: 8}, nil)
	var dummyBytes uint64
	err := sender.Run(ctx, nil, func(_ context.Context, frame []byte) error {
		packets, err := Decode(frame)
		if err != nil {
			return err
		}
		if len(packets) != 0 {
			t.Fatal("dummy decoded as application data")
		}
		dummyBytes += uint64(len(frame))
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected stop: %v", err)
	}
	stats := sender.Snapshot()
	if stats.DummyFrames < 8 || dummyBytes > InitialDummyCredit || stats.InputBytes != 0 || stats.OutputBytes != dummyBytes {
		t.Fatalf("dummy credit violation: %+v, bytes %d", stats, dummyBytes)
	}
}

func TestSenderRealDataIsNotStarvedByWarmup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	input := make(chan []byte)
	firstDummy := make(chan struct{}, 1)
	dataSent := make(chan time.Time, 1)
	sender, _ := NewSender(Policy{WarmupFrames: 8, PaceMinMS: 100}, nil)
	done := make(chan error, 1)
	go func() {
		done <- sender.Run(ctx, input, func(_ context.Context, frame []byte) error {
			packets, err := Decode(frame)
			if err != nil {
				return err
			}
			if len(packets) == 0 {
				select {
				case firstDummy <- struct{}{}:
				default:
				}
			} else {
				if len(packets) != 1 || string(packets[0]) != "real" {
					return errors.New("real datagram changed")
				}
				dataSent <- time.Now()
			}
			return nil
		})
	}()
	select {
	case <-firstDummy:
	case <-ctx.Done():
		t.Fatal("no warmup frame")
	}
	start := time.Now()
	select {
	case input <- []byte("real"):
	case <-ctx.Done():
		t.Fatal("input blocked")
	}
	select {
	case emitted := <-dataSent:
		if emitted.Sub(start) > 200*time.Millisecond {
			t.Fatal("real data starved behind eight warmup frames")
		}
	case <-ctx.Done():
		t.Fatal("real data never emitted")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected stop: %v", err)
	}
}

func TestSenderCancellationReachesBlockedWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan []byte, 1)
	input <- []byte("payload")
	sender, _ := NewSender(Policy{}, nil)
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- sender.Run(ctx, input, func(ctx context.Context, _ []byte) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer not called")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop blocked writer")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{2, 0, 0})
	f.Add([]byte{2, 0, 1, 0, 0})
	f.Add([]byte{2, 0, 1, 0, 3, 'u', 'd', 'p', 0, 0})
	f.Fuzz(func(t *testing.T, frame []byte) {
		packets, err := Decode(frame)
		if err != nil {
			return
		}
		canonical, err := Encode(packets, Policy{}, nil)
		if err != nil {
			t.Fatalf("accepted frame cannot be re-encoded: %v", err)
		}
		again, err := Decode(canonical)
		if err != nil || !reflect.DeepEqual(again, packets) {
			t.Fatal("accepted datagrams do not survive a canonical round trip")
		}
	})
}

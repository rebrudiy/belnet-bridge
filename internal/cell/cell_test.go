package cell

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func packet(n int, seed byte) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*31) ^ seed
	}
	return p
}

func mustPush(t *testing.T, e *Encoder, p []byte) {
	t.Helper()
	if err := e.Push(p); err != nil {
		t.Fatal(err)
	}
}

func mustNext(t *testing.T, e *Encoder, n int) []byte {
	t.Helper()
	p, err := e.Next(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != n {
		t.Fatalf("cell size %d, want %d", len(p), n)
	}
	return p
}

func mustAccept(t *testing.T, d *Decoder, p []byte) [][]byte {
	t.Helper()
	got, err := d.Accept(p)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDatagramBoundariesOrderAndOwnership(t *testing.T) {
	for _, size := range []int{MinSize, 1024, 1536, MaxSize} {
		t.Run(stringSize(size), func(t *testing.T) {
			e, d := NewEncoder(nil), NewDecoder()
			var want [][]byte
			for i, n := range []int{0, 1, MinSize - HeaderSize, MinSize - HeaderSize + 1, 1500, 60000, MaxDatagram} {
				p := packet(n, byte(i))
				want = append(want, append([]byte{}, p...))
				mustPush(t, e, p)
				clear(p) // Push must own a copy, including caller-buffer reuse.
			}
			e.Close()
			var got [][]byte
			for {
				frame, err := e.Next(size)
				if errors.Is(err, ErrDrained) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				completed := mustAccept(t, d, frame)
				clear(frame) // Decoder must not retain aliases to received cells.
				got = append(got, completed...)
			}
			if len(got) != len(want) {
				t.Fatalf("got %d datagrams, want %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) || got[i] == nil {
					t.Fatalf("datagram %d not preserved (%d bytes)", i, len(want[i]))
				}
			}
			s := e.Snapshot()
			if s.InputDatagrams != uint64(len(want)) || s.CompletedDatagrams != uint64(len(want)) || s.QueueBytes != 0 || s.PayloadBytes != s.InputBytes || s.DummyCells != 0 {
				t.Fatalf("incorrect encoder accounting: %+v", s)
			}
			if s.OutputBytes != s.OutputCells*uint64(HeaderSize)+s.PayloadBytes+s.PaddingBytes {
				t.Fatal("cell byte accounting does not balance")
			}
		})
	}
}

func stringSize(n int) string {
	// Keep subtest labels free from a formatting dependency in the codec itself.
	if n == MinSize {
		return "minimum"
	}
	if n == MaxSize {
		return "maximum"
	}
	if n == 1024 {
		return "1024"
	}
	return "1536"
}

func TestDummyAndEmptyDatagramAreDistinct(t *testing.T) {
	e, d := NewEncoder(zeroReader{}), NewDecoder()
	if got := mustAccept(t, d, mustNext(t, e, MinSize)); len(got) != 0 {
		t.Fatal("dummy became a UDP datagram")
	}
	mustPush(t, e, nil)
	got := mustAccept(t, d, mustNext(t, e, MinSize))
	if len(got) != 1 || len(got[0]) != 0 || got[0] == nil {
		t.Fatal("genuine empty datagram lost")
	}
	if e.Snapshot().DummyCells != 1 || d.Snapshot().DummyCells != 1 || d.Snapshot().CompletedDatagrams != 1 {
		t.Fatal("dummy/data accounting mixed")
	}
}

func TestVariableCellSizesPreserveFragmentation(t *testing.T) {
	e, d := NewEncoder(zeroReader{}), NewDecoder()
	want := packet(60000, 17)
	mustPush(t, e, want)
	for i := 0; i < 100; i++ {
		size := []int{256, 8192, 1024, 777}[i%4]
		if got := mustAccept(t, d, mustNext(t, e, size)); len(got) > 0 {
			if !bytes.Equal(got[0], want) {
				t.Fatal("variable cell size damaged datagram")
			}
			return
		}
	}
	t.Fatal("datagram did not complete")
}

func TestQueueAndAllocationBounds(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		e := NewEncoder(zeroReader{})
		for i := 0; i < MaxPending; i++ {
			mustPush(t, e, nil)
		}
		if !errors.Is(e.Push(nil), ErrQueueFull) {
			t.Fatal("unbounded empty datagram queue")
		}
		if e.Snapshot().QueueDatagrams != MaxPending {
			t.Fatal("queue overflow modified count")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		e := NewEncoder(zeroReader{})
		p := packet(MaxDatagram, 1)
		for i := 0; i < MaxPendingBytes/MaxDatagram; i++ {
			mustPush(t, e, p)
		}
		before := e.Snapshot()
		if !errors.Is(e.Push(p), ErrQueueFull) {
			t.Fatal("unbounded datagram bytes")
		}
		if e.Snapshot().QueueBytes != before.QueueBytes || before.QueueBytes > MaxPendingBytes {
			t.Fatal("queue overflow modified bytes")
		}
		if e.Push(make([]byte, MaxDatagram+1)) == nil {
			t.Fatal("oversized UDP accepted")
		}
		mustPush(t, e, nil) // A byte bound must not confuse a valid empty packet.
	})
	t.Run("decoder", func(t *testing.T) {
		e, d := NewEncoder(zeroReader{}), NewDecoder()
		mustPush(t, e, packet(MaxDatagram, 3))
		first := mustNext(t, e, MinSize)
		mustAccept(t, d, first)
		for i := 0; i < 1000; i++ {
			forged := append([]byte(nil), first...)
			binary.BigEndian.PutUint32(forged[4:8], uint32(i+2))
			if !errors.Is(acceptError(d, forged), ErrSequence) {
				t.Fatal("interleaved start accepted")
			}
		}
		s := d.Snapshot()
		if s.PendingDatagrams != 1 || s.PendingBytes != MaxDatagram || s.MaxPendingBytes > MaxPendingBytes {
			t.Fatalf("unbounded reassembly: %+v", s)
		}
	})
}

func acceptError(d *Decoder, frame []byte) error { _, err := d.Accept(frame); return err }

func TestMalformedCellsRejected(t *testing.T) {
	e := NewEncoder(zeroReader{})
	mustPush(t, e, packet(700, 1))
	first := mustNext(t, e, MinSize)
	cases := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short", func(p []byte) []byte { return p[:HeaderSize] }},
		{"oversized", func(p []byte) []byte { return append(p, make([]byte, MaxSize)...) }},
		{"version", func(p []byte) []byte { p[0]++; return p }},
		{"kind", func(p []byte) []byte { p[1] = 9; return p }},
		{"flags", func(p []byte) []byte { p[2] |= 8; return p }},
		{"reserved", func(p []byte) []byte { p[3] = 1; return p }},
		{"reserved-tail", func(p []byte) []byte { p[18] = 1; return p }},
		{"zero-id", func(p []byte) []byte { clear(p[4:8]); return p }},
		{"total", func(p []byte) []byte { binary.BigEndian.PutUint32(p[8:12], MaxDatagram+1); return p }},
		{"offset", func(p []byte) []byte { binary.BigEndian.PutUint32(p[12:16], 701); return p }},
		{"fragment-length", func(p []byte) []byte { binary.BigEndian.PutUint16(p[16:18], MinSize); return p }},
		{"empty-fragment", func(p []byte) []byte { clear(p[16:18]); return p }},
		{"false-end", func(p []byte) []byte { p[2] |= flagEnd; return p }},
		{"missing-start", func(p []byte) []byte { p[2] &= ^byte(flagStart); return p }},
		{"dummy-metadata", func(p []byte) []byte { p[1] = kindDummy; return p }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecoder()
			_, err := d.Accept(tc.change(append([]byte(nil), first...)))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want malformed", err)
			}
			if d.Snapshot().PendingBytes != 0 {
				t.Fatal("malformed cell allocated memory")
			}
		})
	}
}

func TestSequenceOverlapReplayAndUnknownContinuation(t *testing.T) {
	e, d := NewEncoder(zeroReader{}), NewDecoder()
	mustPush(t, e, packet(700, 4))
	first := mustNext(t, e, MinSize)
	second := mustNext(t, e, MinSize)
	if !errors.Is(acceptError(d, second), ErrSequence) {
		t.Fatal("unknown continuation accepted")
	}
	mustAccept(t, d, first)
	if !errors.Is(acceptError(d, first), ErrSequence) {
		t.Fatal("duplicate/overlapping first fragment accepted")
	}
	overlap := append([]byte(nil), second...)
	binary.BigEndian.PutUint32(overlap[12:16], 1)
	if !errors.Is(acceptError(d, overlap), ErrSequence) {
		t.Fatal("overlapping continuation accepted")
	}
	wrongTotal := append([]byte(nil), second...)
	binary.BigEndian.PutUint32(wrongTotal[8:12], 701)
	if !errors.Is(acceptError(d, wrongTotal), ErrSequence) {
		t.Fatal("changed total accepted")
	}
	mustAccept(t, d, second)
	completed := mustAccept(t, d, mustNext(t, e, MinSize))
	if len(completed) != 1 || len(completed[0]) != 700 {
		t.Fatal("valid stream did not survive rejected bad cell")
	}
	if !errors.Is(acceptError(d, first), ErrSequence) {
		t.Fatal("completed datagram replay accepted")
	}
	mustPush(t, e, packet(1, 8))
	next := mustNext(t, e, MinSize)
	mustAccept(t, d, next)
}

func TestReassemblyExpiryAndReset(t *testing.T) {
	e, d := NewEncoder(zeroReader{}), NewDecoder()
	now := time.Unix(1, 0)
	d.clock = func() time.Time { return now }
	mustPush(t, e, packet(700, 1))
	first := mustNext(t, e, MinSize)
	second := mustNext(t, e, MinSize)
	mustAccept(t, d, first)
	now = now.Add(ReassemblyTimeout - time.Nanosecond)
	if d.Expire() {
		t.Fatal("expired too early")
	}
	now = now.Add(time.Nanosecond)
	if !d.Expire() || d.Snapshot().PendingBytes != 0 {
		t.Fatal("reassembly did not expire")
	}
	if !errors.Is(acceptError(d, second), ErrSequence) {
		t.Fatal("expired continuation accepted")
	}
	if !errors.Is(acceptError(d, first), ErrSequence) {
		t.Fatal("expired ID replay accepted")
	}
	d.Reset()
	mustAccept(t, d, first)
	if d.Snapshot().PendingBytes != 700 {
		t.Fatal("reset did not reopen stream epoch")
	}
	d.Reset()
	if d.Snapshot().PendingBytes != 0 || d.Snapshot().ResetDatagrams != 1 {
		t.Fatal("reset did not discard incomplete allocation")
	}
	if d.Snapshot().ExpiredDatagrams != 1 {
		t.Fatal("expiry accounting wrong")
	}
}

func TestCloseAbortAndRewind(t *testing.T) {
	e, d := NewEncoder(zeroReader{}), NewDecoder()
	want := packet(700, 9)
	mustPush(t, e, want)
	mustAccept(t, d, mustNext(t, e, MinSize))
	e.Rewind()
	d.Reset()
	e.Close()
	if !errors.Is(e.Push(nil), ErrClosed) {
		t.Fatal("push after close accepted")
	}
	var got [][]byte
	for {
		p, err := e.Next(MinSize)
		if errors.Is(err, ErrDrained) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, mustAccept(t, d, p)...)
	}
	if len(got) != 1 || !bytes.Equal(got[0], want) || e.Snapshot().Rewinds != 1 {
		t.Fatal("rewind failed")
	}
	e = NewEncoder(zeroReader{})
	mustPush(t, e, want)
	e.Abort()
	if !errors.Is(e.Push(nil), ErrClosed) {
		t.Fatal("push after abort accepted")
	}
	if _, err := e.Next(MinSize); !errors.Is(err, ErrDrained) {
		t.Fatal("abort did not stop immediate next")
	}
	if e.Snapshot().AbortedDatagrams != 1 || e.Snapshot().QueueBytes != 0 {
		t.Fatal("abort left pending data")
	}
}

func TestSizeAndRandomErrorsDoNotConsumeQueue(t *testing.T) {
	e := NewEncoder(brokenReader{})
	mustPush(t, e, packet(300, 4))
	for _, size := range []int{-1, 0, MinSize - 1, MaxSize + 1} {
		if _, err := e.Next(size); err == nil {
			t.Fatal("bad cell size accepted")
		}
	}
	if _, err := e.Next(MinSize); err == nil {
		t.Fatal("randomness error hidden")
	}
	if e.Snapshot().OutputCells != 0 || e.Snapshot().QueueDatagrams != 1 || e.queue[0].offset != 0 {
		t.Fatal("failed encoding consumed input")
	}
	e.random = zeroReader{}
	d := NewDecoder()
	mustAccept(t, d, mustNext(t, e, MaxSize))
	if d.Snapshot().CompletedBytes != 300 {
		t.Fatal("queue damaged by previous failures")
	}
}

func TestIdentifierWrap(t *testing.T) {
	e, d := NewEncoder(zeroReader{}), NewDecoder()
	e.nextID = math.MaxUint32 - 1
	for _, id := range []uint32{math.MaxUint32 - 1, math.MaxUint32, 1} {
		mustPush(t, e, []byte{1})
		p := mustNext(t, e, MinSize)
		if binary.BigEndian.Uint32(p[4:8]) != id {
			t.Fatal("unexpected ID wrap")
		}
		mustAccept(t, d, p)
	}
}

func TestConcurrentProducerSenderAndSnapshots(t *testing.T) {
	e, d := NewEncoder(nil), NewDecoder()
	defer e.Abort()
	const count = 300
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			p := make([]byte, 32)
			binary.BigEndian.PutUint32(p, uint32(i))
			for {
				err := e.Push(p)
				if err == nil {
					break
				}
				if !errors.Is(err, ErrQueueFull) {
					t.Errorf("push: %v", err)
					return
				}
				runtime.Gosched()
			}
		}
		e.Close()
	}()
	stop := make(chan struct{})
	var snapshots sync.WaitGroup
	defer func() {
		close(stop)
		e.Abort()
		snapshots.Wait()
		wg.Wait()
	}()
	snapshots.Add(1)
	go func() {
		defer snapshots.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.Snapshot()
				d.Snapshot()
				runtime.Gosched()
			}
		}
	}()
	got := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p, err := e.Next(MinSize)
		if errors.Is(err, ErrDrained) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, packet := range mustAccept(t, d, p) {
			if binary.BigEndian.Uint32(packet) != uint32(got) {
				t.Fatal("datagram order changed")
			}
			got++
		}
	}
	if got != count {
		t.Fatalf("got %d datagrams, want %d", got, count)
	}
}

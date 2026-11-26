package traffic

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func tlsRecord(kind byte, payload string) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = kind
	b[1] = 3
	b[2] = 3
	binary.BigEndian.PutUint16(b[3:5], uint16(len(payload)))
	copy(b[5:], payload)
	return b
}

func TestRecorderReassemblesArbitraryCiphertextChunks(t *testing.T) {
	now := time.Unix(100, 0)
	r := NewRecorder()
	r.clock = func() time.Time { return now }
	handshake := tlsRecord(22, "plaintext handshake is excluded")
	one := tlsRecord(23, "first ciphertext")
	two := tlsRecord(23, "second ciphertext")
	wire := append(append(handshake, one...), two...)
	for _, b := range wire {
		r.observe(1, []byte{b})
	}
	now = now.Add(10 * time.Millisecond)
	r.observe(-1, tlsRecord(23, "response ciphertext"))
	want := []Event{{0, 1, len(one)}, {0, 1, len(two)}, {10000, -1, 24}}
	if got := r.EventsSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %+v, want %+v", got, want)
	}
	snapshot := r.EventsSnapshot()
	snapshot[0].Bytes = 0
	if r.EventsSnapshot()[0].Bytes == 0 {
		t.Fatal("caller mutated recorder")
	}
	if r.Ready() {
		t.Fatal("window ready early")
	}
	now = now.Add(Window)
	if !r.Ready() {
		t.Fatal("time window did not close")
	}
	r.observe(1, tlsRecord(23, "outside window"))
	if len(r.EventsSnapshot()) != 3 {
		t.Fatal("observed record outside time window")
	}
}

func TestRecorderCoalescedRecordsShareObservationTimeAndBound(t *testing.T) {
	r := NewRecorder()
	clockCalls := 0
	r.clock = func() time.Time { clockCalls++; return time.Unix(100, int64(clockCalls)*1000) }
	record := tlsRecord(23, "encrypted")
	r.observe(1, bytes.Repeat(record, MaxRecords+10))
	if len(r.EventsSnapshot()) != MaxRecords || !r.Ready() {
		t.Fatal("record bound not applied")
	}
	for _, e := range r.EventsSnapshot() {
		if e.AtMicros != 0 {
			t.Fatal("fabricated per-record timing within one read")
		}
	}
	if clockCalls != 1 {
		t.Fatalf("clock called %d times for one wire observation", clockCalls)
	}
}

func TestRecorderRejectsMalformedOuterTLSHeader(t *testing.T) {
	r := NewRecorder()
	r.observe(1, []byte("HTTP/1.1 200 OK\r\n"))
	if !r.Malformed() || len(r.EventsSnapshot()) != 0 {
		t.Fatal("non-TLS stream accepted")
	}
	r.observe(-1, tlsRecord(23, "later bytes must not resync"))
	if len(r.EventsSnapshot()) != 0 {
		t.Fatal("malformed stream silently resynchronized")
	}
}

func TestObserveConnMapsClientAndServerDirections(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	clientRecorder, serverRecorder := NewRecorder(), NewRecorder()
	client := ObserveConn(left, true, clientRecorder)
	server := ObserveConn(right, false, serverRecorder)
	first := tlsRecord(23, "outbound ciphertext")
	second := tlsRecord(23, "inbound ciphertext")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(first))
		_, _ = io.ReadFull(server, buf)
		_, _ = server.Write(second)
	}()
	if _, err := client.Write(first); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, len(second))); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for _, r := range []*Recorder{clientRecorder, serverRecorder} {
		e := r.EventsSnapshot()
		if len(e) != 2 || e[0].Direction != 1 || e[1].Direction != -1 || e[0].Bytes != len(first) || e[1].Bytes != len(second) {
			t.Fatalf("wrong directional observation %+v", e)
		}
	}
}

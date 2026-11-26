package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const epochNS = int64(1_700_000_000) * 1_000_000_000

func metadata() Metadata {
	zero := uint64(0)
	return Metadata{GroupID: "fixture-group", Split: "train", Class: "benign", Profile: "fixture", ServerPorts: []uint16{443}, CaptureStarted: utc(epochNS), CaptureEnded: utc(epochNS + int64(45*time.Second)), Dropped: &zero, FreezeSHA: "fixture-frozen-before-generation"}
}

type fixture struct {
	buf  bytes.Buffer
	nano bool
}

func newFixture(nano bool) *fixture {
	f := &fixture{nano: nano}
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	for _, v := range []any{magic, uint16(2), uint16(4), uint32(0), uint32(0), uint32(262144), uint32(1)} {
		if err := binary.Write(&f.buf, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
	return f
}
func tcp(direction int, seq uint32, flags byte, payload []byte) []byte {
	p := make([]byte, 14+20+20+len(payload))
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	ip := p[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 6
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	sport, dport := uint16(30000), uint16(443)
	if direction == -1 {
		sport, dport = dport, sport
		copy(ip[12:16], []byte{10, 0, 0, 2})
		copy(ip[16:20], []byte{10, 0, 0, 1})
	}
	t := ip[20:]
	binary.BigEndian.PutUint16(t[:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	binary.BigEndian.PutUint32(t[4:8], seq)
	t[12] = 5 << 4
	t[13] = flags
	copy(t[20:], payload)
	return p
}
func record(body int) []byte {
	b := make([]byte, body+5)
	copy(b, []byte{23, 3, 3})
	binary.BigEndian.PutUint16(b[3:5], uint16(body))
	for i := 5; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}
func (f *fixture) packet(at int64, p []byte) {
	at += epochNS
	fraction := uint32(at % 1_000_000_000)
	if !f.nano {
		fraction /= 1000
	}
	for _, v := range []uint32{uint32(at / 1_000_000_000), fraction, uint32(len(p)), uint32(len(p))} {
		if err := binary.Write(&f.buf, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
	f.buf.Write(p)
}
func (f *fixture) syn() { f.packet(0, tcp(1, 100, 2, nil)); f.packet(100_000, tcp(-1, 400, 18, nil)) }
func (f *fixture) read(t *testing.T, meta Metadata) Report {
	t.Helper()
	p, err := newParser(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.read(bytes.NewReader(f.buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	return p.finalize()
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

func TestHighRateAllLateWindowsSurvive(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := map[int]uint32{1: 101, -1: 401}
	for i := 0; i < 30_000; i++ {
		direction := 1
		if i%2 == 1 {
			direction = -1
		}
		r := record(100)
		f.packet(int64(i+1)*1_000_000, tcp(direction, seq[direction], 24, r))
		seq[direction] += uint32(len(r))
	}
	f.packet(int64(44*time.Second), tcp(1, seq[1], 16, nil))
	report := f.read(t, metadata())
	if !report.CoverageComplete {
		t.Fatal(report.GlobalReasons, report.GroupWindows)
	}
	if report.Flows[0].Records != 30_000 {
		t.Fatal("record-count truncation", report.Flows[0].Records)
	}
	if report.PendingHighWater != 0 {
		t.Fatal("in-order bytes unnecessarily retained")
	}
	if report.SelectedHighWater > 5*64 {
		t.Fatal("selected events unbounded")
	}
	for _, w := range report.Flows[0].Windows {
		if w.TotalRecords < 1900 || len(w.Events) != 64 || !w.Eligible || !w.SelectionTruncated {
			t.Fatalf("late or prefix window lost: %+v", w)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("payload")) {
		t.Fatal("payload export")
	}
}
func TestReassemblyRecordCompletionAndDuplicate(t *testing.T) {
	f := newFixture(false)
	f.syn()
	r := record(40)
	f.packet(1_000_000, tcp(1, 105, 24, r[4:]))
	f.packet(2_000_000, tcp(1, 105, 24, r[4:]))
	f.packet(3_000_000, tcp(1, 101, 24, r[:4]))
	report := f.read(t, metadata())
	flow := report.Flows[0]
	if flow.Records != 1 || flow.First.UnixNano() != epochNS+3_000_000 {
		t.Fatal("wrong record-completion time or duplicate")
	}
	if flow.Retransmitted == 0 || report.PendingHighWater > len(r) {
		t.Fatal("bad bounded duplicate accounting")
	}
	if !report.CoverageComplete {
		t.Fatal(flow.Issues)
	}
}
func TestGapOverlapAndMemoryBounds(t *testing.T) {
	t.Run("conflicting-gap-fill", func(t *testing.T) {
		f := newFixture(true)
		f.syn()
		r := record(30)
		f.packet(1_000_000, tcp(1, 106, 24, r[5:]))
		r[10] ^= 1
		f.packet(2_000_000, tcp(1, 101, 24, r))
		report := f.read(t, metadata())
		if !contains(report.Flows[0].Issues, "tcp_overlap_conflict") {
			t.Fatal("overlap not rejected")
		}
	})
	t.Run("pending-global-cap", func(t *testing.T) {
		p, err := newParser(metadata())
		if err != nil {
			t.Fatal(err)
		}
		p.maxGlobal = 16
		p.packet(tcp(1, 100, 2, nil), 1, epochNS)
		p.packet(tcp(-1, 400, 18, nil), 1, epochNS+100)
		p.packet(tcp(1, 110, 24, record(40)), 1, epochNS+1000)
		if p.pendingBytes > 16 || !contains(p.report.Flows[0].Issues, "reassembly_byte_censored") {
			t.Fatal("unbounded allocation", p.pendingBytes)
		}
	})
	t.Run("unresolved-gap", func(t *testing.T) {
		f := newFixture(true)
		f.syn()
		r := record(10)
		f.packet(1_000_000, tcp(1, 101, 24, r))
		f.packet(500_000_000, tcp(1, 200, 24, r))
		report := f.read(t, metadata())
		if report.CoverageComplete || !contains(report.Flows[0].Issues, "tcp_reassembly_gap") {
			t.Fatal("gap interpreted as complete")
		}
	})
}
func TestSparseIsDifferentFromCensored(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(20)))
	r := f.read(t, metadata())
	if !r.CoverageComplete {
		t.Fatal("full sparse capture rejected")
	}
	if r.GroupWindows[3].Status != "sparse" || !r.GroupWindows[3].Eligible {
		t.Fatal("sparse window marked missing")
	}
	meta := metadata()
	meta.CapHit = true
	r = f.read(t, meta)
	if r.CoverageComplete || r.GroupWindows[3].Status != "byte_censored" {
		t.Fatal("byte cap was not distinct")
	}
	meta = metadata()
	n := uint64(1)
	meta.Dropped = &n
	r = f.read(t, meta)
	if r.CoverageComplete || !contains(r.GlobalReasons, "capture_packet_drops") {
		t.Fatal("capture drops ignored")
	}
	meta = metadata()
	meta.CaptureEnded = utc(epochNS + int64(9*time.Second))
	r = f.read(t, meta)
	if r.GroupWindows[1].Eligible {
		t.Fatal("late window without end proof accepted")
	}
}
func TestMalformedMissingSYNAndTruncatedPCAP(t *testing.T) {
	f := newFixture(true)
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	r := f.read(t, metadata())
	if !contains(r.Flows[0].Issues, "missing_syn") || r.CoverageComplete {
		t.Fatal("missing SYN accepted")
	}
	f = newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, []byte("GET / private-token HTTP/1.1\r\n")))
	r = f.read(t, metadata())
	if !contains(r.Flows[0].Issues, "malformed_tls") {
		t.Fatal("plaintext not rejected")
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "private-token") {
		t.Fatal("plaintext leaked")
	}
	f = newFixture(true)
	f.syn()
	f.buf.Write([]byte{1, 2, 3})
	r = f.read(t, metadata())
	if !contains(r.GlobalReasons, "truncated_pcap") {
		t.Fatal("truncation hidden")
	}
}
func TestFlowCountCapAndTupleReconnect(t *testing.T) {
	p, _ := newParser(metadata())
	for i := 0; i < MaxFlows+10; i++ {
		packet := tcp(1, uint32(100+i), 2, nil)
		binary.BigEndian.PutUint16(packet[34:36], uint16(10000+i))
		p.packet(packet, 1, epochNS+int64(i))
	}
	if len(p.report.Flows) != MaxFlows || !contains(p.global, "flow_count_censored") {
		t.Fatal("flow count unbounded")
	}
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	f.packet(int64(10*time.Second), tcp(1, 1000, 2, nil))
	f.packet(int64(10*time.Second)+1000, tcp(-1, 4000, 18, nil))
	f.packet(int64(10*time.Second)+2000, tcp(1, 1001, 24, record(10)))
	r := f.read(t, metadata())
	if len(r.Flows) != 2 || r.Flows[1].First == nil {
		t.Fatal("reconnect lost")
	}
	prefix := 0
	for _, w := range r.Flows[1].Windows {
		if w.Kind == "flow-prefix" {
			prefix++
		}
	}
	if prefix != 1 {
		t.Fatal("new flow prefix missing")
	}
}
func TestInvalidMetadataAndNoPayloadFileExport(t *testing.T) {
	m := metadata()
	m.Split = "unknown"
	if _, err := newParser(m); err == nil {
		t.Fatal("bad split accepted")
	}
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, f.buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := extract(path, metadata())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.PCAPSHA) != 64 {
		t.Fatal(fmt.Sprintf("missing provenance: %+v", r.PCAPSHA))
	}
}

func TestIPv6AndLinuxCookedLinkTypes(t *testing.T) {
	for _, kind := range []string{"ipv6-ethernet", "sll", "sll2"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(true)
			transform := func(packet []byte) []byte { return packet }
			switch kind {
			case "ipv6-ethernet":
				transform = func(packet []byte) []byte {
					tcpbytes := packet[34:]
					v6 := make([]byte, 14+40+len(tcpbytes))
					binary.BigEndian.PutUint16(v6[12:14], 0x86dd)
					ip := v6[14:]
					ip[0] = 0x60
					binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcpbytes)))
					ip[6] = 6
					ip[8], ip[9], ip[10], ip[11] = 0x20, 1, 0x0d, 0xb8
					ip[24], ip[25], ip[26], ip[27] = 0x20, 1, 0x0d, 0xb8
					ip[23], ip[39] = packet[29], packet[33]
					copy(ip[40:], tcpbytes)
					return v6
				}
			case "sll", "sll2":
				prefix, link := 16, uint32(113)
				if kind == "sll2" {
					prefix, link = 20, 276
				}
				binary.LittleEndian.PutUint32(f.buf.Bytes()[20:24], link)
				transform = func(packet []byte) []byte {
					out := make([]byte, prefix+len(packet)-14)
					copy(out[prefix:], packet[14:])
					return out
				}
			}
			f.packet(0, transform(tcp(1, 100, 2, nil)))
			f.packet(100_000, transform(tcp(-1, 400, 18, nil)))
			f.packet(1_000_000, transform(tcp(1, 101, 24, record(10))))
			report := f.read(t, metadata())
			if !report.CoverageComplete || report.Flows[0].Records != 1 {
				t.Fatalf("link parser failed %+v", report.GlobalReasons)
			}
		})
	}
}

func TestCaptureGraceCompletesExistingPrefixesWithoutNewObligations(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	// New connection during measurement: its 44–46 s prefix needs grace.
	f.packet(int64(44*time.Second), tcp(1, 1000, 2, nil))
	f.packet(int64(44*time.Second)+1000, tcp(-1, 4000, 18, nil))
	f.packet(int64(44*time.Second)+2000, tcp(1, 1001, 24, record(10)))
	// Another connection during grace must not recursively extend the capture.
	f.packet(int64(46*time.Second), tcp(1, 2000, 2, nil))
	f.packet(int64(46*time.Second)+1000, tcp(-1, 5000, 18, nil))
	f.packet(int64(46*time.Second)+2000, tcp(1, 2001, 24, record(10)))
	meta := metadata()
	meta.CaptureEnded = utc(epochNS + int64(47*time.Second))
	meta.PrefixGraceSeconds = 2
	r := f.read(t, meta)
	if !r.CoverageComplete {
		t.Fatal("grace did not complete measured prefixes", r.GlobalReasons)
	}
	prefix := r.Flows[2].Windows[len(r.Flows[2].Windows)-1]
	if prefix.Kind != "flow-prefix" || prefix.Status != "not_applicable" {
		t.Fatal("grace introduced new obligation", prefix)
	}
	meta.CaptureEnded = utc(epochNS + int64(45*time.Second))
	r = f.read(t, meta)
	if r.CoverageComplete {
		t.Fatal("missing measured prefix end accepted")
	}
}

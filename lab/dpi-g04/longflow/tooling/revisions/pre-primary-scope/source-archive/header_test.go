package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func streamAt(t *testing.T, r Report, direction int) StreamEvidence {
	t.Helper()
	for _, s := range r.Flows[0].Streams {
		if s.Direction == direction {
			return s
		}
	}
	t.Fatal("missing stream", direction)
	return StreamEvidence{}
}
func withACK(packet []byte, ack uint32) []byte {
	binary.BigEndian.PutUint32(packet[42:46], ack)
	return packet
}
func TestHeaderAvailableBeforeBodyAndDeclaredBytes(t *testing.T) {
	f := newFixture(true)
	f.syn()
	r := record(100)
	f.packet(1_000_000, tcp(1, 101, 24, r[:5]))
	f.packet(100_000_000, tcp(1, 106, 24, r[5:]))
	got := f.read(t, setupMetadata())
	if !got.CoverageComplete || got.Flows[0].Records != 1 || got.Flows[0].First.UnixNano() != epochNS+1_000_000 {
		t.Fatal(got.GlobalReasons, got.Flows[0])
	}
	var prefix *Window
	for _, w := range got.Flows[0].Windows {
		if w.Kind == "flow-prefix" {
			prefix = w
		}
	}
	if prefix == nil || len(prefix.Events) != 1 || prefix.Events[0].Bytes != 105 || prefix.Events[0].RawNS != epochNS+1_000_000 || prefix.Events[0].Ordinal != 1 {
		t.Fatal(prefix)
	}
	raw, _ := json.Marshal(got)
	if bytes.Contains(raw, []byte(`"first_tls23_utc"`)) || bytes.Contains(raw, []byte(`"group_first_tls23_utc"`)) {
		t.Fatal("body-completion legacy field exported")
	}
	if got.EvidenceUnit != "tls23_header_declared_length" {
		t.Fatal("unit missing")
	}
}
func TestFragmentedHeaderAndOutOfOrderRequiredPrefixAvailability(t *testing.T) {
	f := newFixture(true)
	f.syn()
	r := record(100)
	next := record(20)
	f.packet(1_000_000, tcp(1, 101, 24, r[:2]))
	f.packet(2_000_000, tcp(1, 103, 24, r[2:25]))
	f.packet(3_000_000, tcp(1, 206, 24, next))
	f.packet(4_000_000, tcp(1, 126, 24, r[25:]))
	got := f.read(t, setupMetadata())
	if !got.CoverageComplete || got.Flows[0].Records != 2 || got.Flows[0].First.UnixNano() != epochNS+2_000_000 {
		t.Fatal(got.GlobalReasons, got.Flows[0].Issues)
	}
	for _, w := range got.Flows[0].Windows {
		if w.Kind == "flow-prefix" {
			if len(w.Events) != 2 || w.Events[1].RawNS != epochNS+4_000_000 {
				t.Fatal("next header before required body prefix", w.Events)
			}
		}
	}
}
func TestOpenPartialBodyKnownHeaderRemainsHeaderViewComplete(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(21)[:6]))
	got := f.read(t, setupMetadata())
	s := streamAt(t, got, 1)
	if !got.CoverageComplete || got.HeaderEvidenceAbsent || got.Flows[0].PrimaryTLS23Headers != 1 || !s.OpenBodyInProgress || s.PartialBodyKnownAbort || s.BodyBytesRemaining != 20 || s.HeaderBytesPending != 0 {
		t.Fatal(got.GlobalReasons, s)
	}
}
func TestVerifiedClosePartialBodyIsKnownAbortNotTLSCompletion(t *testing.T) {
	for _, fin := range []bool{false, true} {
		f := newFixture(true)
		f.syn()
		f.packet(1_000_000, tcp(1, 101, 24, record(21)[:6]))
		if fin {
			f.packet(2_000_000, tcp(1, 107, 17, nil))
		} else {
			f.packet(2_000_000, tcp(-1, 401, 20, nil))
		}
		got := f.read(t, setupMetadata())
		s := streamAt(t, got, 1)
		if !got.CoverageComplete || !s.PartialBodyKnownAbort || s.OpenBodyInProgress || s.BodyBytesRemaining != 20 {
			t.Fatal(fin, got.GlobalReasons, s)
		}
	}
}
func TestHalfCloseDoesNotPretendOtherDirectionAborted(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(20)))
	f.packet(2_000_000, tcp(-1, 401, 24, record(21)[:6]))
	f.packet(3_000_000, tcp(1, 126, 17, nil))
	got := f.read(t, setupMetadata())
	s := streamAt(t, got, -1)
	if !got.CoverageComplete || s.CloseCaptured || s.PartialBodyKnownAbort || !s.OpenBodyInProgress || got.Flows[0].Closed != nil {
		t.Fatal(got.GlobalReasons, s)
	}
}
func TestClosedPartialHeaderAbstainsWithoutFakeHeaderOrAnchor(t *testing.T) {
	for _, kind := range []byte{21, 22, 23} {
		f := newFixture(true)
		f.syn()
		r := record(21)
		r[0] = kind
		f.packet(1_000_000, tcp(1, 101, 24, r[:4]))
		f.packet(2_000_000, tcp(1, 105, 17, nil))
		got := f.read(t, setupMetadata())
		s := streamAt(t, got, 1)
		if !got.CoverageComplete || !got.HeaderEvidenceAbsent || got.GroupAnchor != nil || got.Flows[0].Records != 0 || got.Flows[0].RawTCPPayloadBytes != 4 || !s.PartialHeaderClosedAbstention || s.HeaderBytesPending != 4 {
			t.Fatal(kind, got.GlobalReasons, s)
		}
	}
}
func TestOpenPartialHeaderRemainsUnknownAndMalformedPrefixNeverAbstains(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		f := newFixture(true)
		f.syn()
		data := record(21)[:4]
		if malformed {
			data[0] = 99
		}
		f.packet(1_000_000, tcp(1, 101, 24, data))
		if malformed {
			f.packet(2_000_000, tcp(1, 105, 17, nil))
		}
		got := f.read(t, setupMetadata())
		want := "partial_final_tls_header"
		if malformed {
			want = "malformed_tls"
		}
		if got.CoverageComplete || got.HeaderEvidenceAbsent || !contains(got.Flows[0].Issues, want) {
			t.Fatal(malformed, got.GlobalReasons, got.Flows[0].Issues)
		}
	}
}
func TestHandshakeOrAlertPayloadHasValidatedNoTLS23HeaderEvidence(t *testing.T) {
	for _, kind := range []byte{21, 22} {
		for _, partial := range []bool{false, true} {
			f := newFixture(true)
			f.syn()
			r := record(21)
			r[0] = kind
			if partial {
				r = r[:6]
			}
			f.packet(1_000_000, tcp(1, 101, 24, r))
			got := f.read(t, setupMetadata())
			if !got.CoverageComplete || !got.HeaderEvidenceAbsent || got.GroupAnchor != nil || got.Flows[0].TLSHeaders != 1 || got.Flows[0].Records != 0 || got.Flows[0].RawTCPPayloadBytes == 0 {
				t.Fatal(kind, partial, got.GlobalReasons)
			}
		}
	}
}
func TestFINSequenceAndAcknowledgedFINPlusOne(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(20)))
	f.packet(2_000_000, tcp(1, 126, 17, nil))
	f.packet(3_000_000, withACK(tcp(-1, 401, 16, nil), 127))
	got := f.read(t, setupMetadata())
	s := streamAt(t, got, 1)
	if !got.CoverageComplete || !got.Flows[0].TCPSequenceCensusComplete || s.MaxPeerAcknowledgedBytes != 25 || !s.CloseSequenceValid {
		t.Fatal(got.GlobalReasons, s)
	}
}
func TestCloseOrACKProvingUncapturedTCPBytesIsUnknown(t *testing.T) {
	for _, mode := range []string{"fin_gap", "ack_gap", "rst_badseq"} {
		f := newFixture(true)
		f.syn()
		hello := record(21)
		hello[0] = 22
		f.packet(1_000_000, tcp(1, 101, 24, hello[:4]))
		switch mode {
		case "fin_gap":
			f.packet(2_000_000, tcp(1, 106, 17, nil))
		case "ack_gap":
			f.packet(2_000_000, withACK(tcp(-1, 401, 20, nil), 110))
		case "rst_badseq":
			f.packet(2_000_000, tcp(-1, 499, 20, nil))
		}
		got := f.read(t, setupMetadata())
		if got.CoverageComplete || got.HeaderEvidenceAbsent || got.Flows[0].TCPSequenceCensusComplete {
			t.Fatal(mode, got.GlobalReasons, got.Flows[0].Issues)
		}
	}
}
func TestConsumedOverlapConflictAndRetransmissionBeyond64KiBAreExact(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		f := newFixture(true)
		f.syn()
		r := record(100)
		seq := uint32(101)
		for i := 0; i < 1000; i++ {
			f.packet(int64(i+1)*1_000_000, tcp(1, seq, 24, r))
			seq += uint32(len(r))
		}
		dup := append([]byte{}, r...)
		if conflict {
			dup[20] ^= 1
		}
		f.packet(int64(2*time.Second), tcp(1, 101, 24, dup))
		got := f.read(t, setupMetadata())
		if conflict {
			if got.CoverageComplete || !contains(got.Flows[0].Issues, "tcp_overlap_conflict") {
				t.Fatal("consumed conflict hidden")
			}
		} else if !got.CoverageComplete || got.ConsumedHistoryHighWater != 105000 || got.Flows[0].Records != 1000 {
			t.Fatal("old retransmission falsely censored", got.GlobalReasons, got.ConsumedHistoryHighWater)
		}
	}
}
func TestHeaderAbsenceCannotWaiveCaptureDropsOrMissingHandshake(t *testing.T) {
	f := newFixture(true)
	f.syn()
	hello := record(21)
	hello[0] = 22
	f.packet(1_000_000, tcp(1, 101, 24, hello))
	m := setupMetadata()
	drops := uint64(1)
	m.Dropped = &drops
	got := f.read(t, m)
	if got.CoverageComplete || got.HeaderEvidenceAbsent {
		t.Fatal("drops waived")
	}
}

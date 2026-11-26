package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestHeaderLongflowCountsDeclaredLengthBeforeLastBodyCompletion(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := uint32(101)
	for i := 0; i < 16; i++ {
		r := record(21)
		f.packet(int64(i+1)*20_000_000, tcp(1, seq, 24, r))
		seq += uint32(len(r))
	}
	f.packet(400_000_000, tcp(1, seq, 24, record(21)[:6]))
	got := summarize(extractFixture(t, f, fullMetadata()))
	if !got.ParserCoverage || got.PrimaryRecords != 17 || got.Group.Statistics.TLSBytes != 17*26 || got.EvidenceUnit != "tls23_header_declared_length" {
		t.Fatal(got.ParserCoverage, got.PrimaryRecords, got.Group.Statistics)
	}
	if !got.Flows[0].Streams[0].OpenBodyInProgress || got.Flows[0].Streams[0].PartialBodyKnownAbort || got.Flows[0].RawTCPPayloadBytes != 16*26+6 {
		t.Fatal(got.Flows[0])
	}
	v := got.Flows[0].Features["lf01_exact26_share"]
	if !v.Eligible || v.Value == nil || *v.Value != 1 {
		t.Fatal("header formula not applied", v)
	}
	raw, _ := json.Marshal(got)
	for _, old := range []string{`"first_tls23_utc"`, `"first_record_completion_unix_ns"`, `"tls_record_bytes"`} {
		if bytes.Contains(raw, []byte(old)) {
			t.Fatal("ambiguous legacy body field", old)
		}
	}
}
func TestHeaderLongflowAmbiguityMasksLF05EvenWithDifferentBodyProgress(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := map[int]uint32{1: 101, -1: 401}
	for i := 0; i < 16; i++ {
		d := 1
		if i%2 == 1 {
			d = -1
		}
		r := record(21)
		f.packet(int64(i+1)*1_000_000, tcp(d, seq[d], 24, r))
		seq[d] += uint32(len(r))
	}
	f.packet(20_000_000, tcp(1, seq[1], 24, record(100)[:5]))
	f.packet(20_000_500, tcp(-1, seq[-1], 24, record(21)[:6]))
	got := summarize(extractFixture(t, f, fullMetadata()))
	if !got.ParserCoverage || got.PrimaryRecords != 18 || !got.Flows[0].OrderingAmbiguous || got.Flows[0].Features["lf05_immediate_reply_share"].Eligible {
		t.Fatal("header projected tie was not masked", got.Flows[0])
	}
	if !got.Flows[0].Features["lf01_exact26_share"].Eligible {
		t.Fatal("ambiguity erased unrelated feature")
	}
}
func TestHeaderLongflowClosedPartialHeaderAbstainsWithActualFlowRetained(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(21)[:4]))
	f.packet(2_000_000, tcp(1, 105, 17, nil))
	got := summarize(extractFixture(t, f, fullMetadata()))
	if !got.ParserCoverage || !got.HeaderEvidenceAbsent || got.PrimaryRecords != 0 || len(got.Flows) != 1 || !got.Flows[0].HeaderEvidenceAbsent || !got.Flows[0].Streams[0].PartialHeaderClosedAbstention || got.GroupFirstHeaderAvailable != nil {
		t.Fatal(got)
	}
	for _, v := range got.Flows[0].Features {
		if v.Eligible || v.Value != nil {
			t.Fatal("fabricated no-header feature", v)
		}
	}
}

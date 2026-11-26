package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func setupMetadata() Metadata {
	m := metadata()
	m.MeasurementStartMicros = epochNS / 1000
	m.PrefixGraceSeconds = 2
	m.CaptureEnded = utc(epochNS + int64(47*time.Second))
	return m
}

func TestZeroPayloadSYNAndRSTAreEvidenceAbstention(t *testing.T) {
	for _, rst := range []bool{false, true} {
		f := newFixture(true)
		f.packet(1000, tcp(1, 100, 2, nil))
		if rst {
			f.packet(2000, tcp(-1, 0, 20, nil))
		}
		got := f.read(t, setupMetadata())
		if !got.CoverageComplete || !got.ZeroPayloadSetupOnly || got.GroupAnchor != nil || len(got.Flows) != 1 {
			t.Fatalf("pure attempt UNKNOWN or fake anchor: %+v", got.GlobalReasons)
		}
		row := got.Flows[0]
		if row.RawTCPPayloadBytes != 0 || row.SetupState != "setup_incomplete_no_tls_evidence" || row.SYNACK || row.RSTCaptured != rst || !row.PrimaryScope || contains(row.Issues, "missing_syn_ack") {
			t.Fatalf("bad setup diagnostics: %+v", row)
		}
		if got.CoverageSHA != CoverageSemanticsSHA || got.Schema != 6 {
			t.Fatal("unpinned coverage semantics")
		}
		havePrimary := false
		for _, w := range row.Windows {
			if w.Primary && w.Status != "not_applicable" {
				havePrimary = true
				if len(w.Events) != 0 || w.TotalRecords != 0 || w.Status != "sparse" {
					t.Fatal("invented evidence")
				}
			}
		}
		if !havePrimary {
			t.Fatal("actual attempt lost from denominator")
		}
	}
}

func TestPayloadMissingSYNACKIncludingTFOStaysUnknown(t *testing.T) {
	for _, mode := range []string{"tls23", "clienthello", "tfo_tls23", "tfo_clienthello", "downstream_without_synack"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(true)
			payload := record(21)
			if mode == "clienthello" || mode == "tfo_clienthello" {
				payload[0] = 22
			}
			flags := byte(2)
			synPayload := []byte(nil)
			if mode == "tfo_tls23" || mode == "tfo_clienthello" {
				synPayload = payload
			}
			f.packet(1000, tcp(1, 100, flags, synPayload))
			if synPayload == nil {
				d := 1
				seq := uint32(101)
				if mode == "downstream_without_synack" {
					d = -1
					seq = 401
				}
				f.packet(2000, tcp(d, seq, 24, payload))
			}
			got := f.read(t, setupMetadata())
			row := got.Flows[0]
			if got.CoverageComplete || got.ZeroPayloadSetupOnly || row.RawTCPPayloadBytes != uint64(len(payload)) || !contains(row.Issues, "missing_syn_ack") || row.SetupState != "payload_observed" {
				t.Fatalf("payload escaped guard: %s %+v %+v", mode, row, got.GlobalReasons)
			}
		})
	}
}

func TestACKOrRSTWithoutInitialSYNStayUnknown(t *testing.T) {
	for _, flags := range []byte{16, 4, 20} {
		f := newFixture(true)
		f.packet(1000, tcp(1, 101, flags, nil))
		got := f.read(t, setupMetadata())
		if got.CoverageComplete || got.ZeroPayloadSetupOnly || !contains(got.Flows[0].Issues, "missing_syn") || got.Flows[0].SetupState != "unknown_missing_initial_syn" {
			t.Fatal("no initial SYN was accepted")
		}
	}
}

func TestZeroPayloadAttemptDoesNotHideCaptureOrCausalFailure(t *testing.T) {
	f := newFixture(true)
	f.packet(2000, tcp(1, 100, 2, nil))
	f.packet(1000, tcp(1, 100, 2, nil))
	got := f.read(t, setupMetadata())
	if got.CoverageComplete || !contains(got.Flows[0].Issues, "non_monotonic_stream_clock") {
		t.Fatal("clock error hidden")
	}
	m := setupMetadata()
	drop := uint64(1)
	m.Dropped = &drop
	g := newFixture(true)
	g.packet(1000, tcp(1, 100, 2, nil))
	got = g.read(t, m)
	if got.CoverageComplete {
		t.Fatal("kernel loss hidden")
	}
}

func TestMixedFailedAttemptAndRealTLSKeepsBothFlowIdentities(t *testing.T) {
	f := newFixture(true)
	f.packet(1000, tcp(1, 100, 2, nil))
	other := func(d int, seq uint32, flags byte, payload []byte) []byte {
		p := tcp(d, seq, flags, payload)
		o := 14 + 20
		if d == 1 {
			binary.BigEndian.PutUint16(p[o:o+2], 30001)
		} else {
			binary.BigEndian.PutUint16(p[o+2:o+4], 30001)
		}
		return p
	}
	f.packet(3000, other(1, 200, 2, nil))
	f.packet(4000, other(-1, 500, 18, nil))
	f.packet(5000, other(1, 201, 24, record(21)))
	got := f.read(t, setupMetadata())
	if !got.CoverageComplete || got.ZeroPayloadSetupOnly || len(got.Flows) != 2 || got.GroupAnchor == nil || got.Flows[0].RawTCPPayloadBytes != 0 {
		t.Fatalf("mixed flow state %+v", got.GlobalReasons)
	}
	for _, flow := range got.Flows {
		if !flow.PrimaryScope {
			t.Fatal("lost primary flow")
		}
	}
}

func TestGraceOnlyAttemptsCannotWaiveNoActivity(t *testing.T) {
	f := newFixture(true)
	f.packet(int64(46*time.Second), tcp(1, 100, 2, nil))
	got := f.read(t, setupMetadata())
	if got.CoverageComplete || got.ZeroPayloadSetupOnly || got.Flows[0].PrimaryScope || !contains(got.GlobalReasons, "no_tls23_group_anchor") {
		t.Fatal("grace created primary activity")
	}
	for _, w := range got.Flows[0].Windows {
		if w.Primary && w.Status != "not_applicable" {
			t.Fatal("grace flow entered primary denominator")
		}
	}
}

func TestPayloadRetransmitsAndSequenceGapsRemainStrict(t *testing.T) {
	f := newFixture(true)
	f.syn()
	payload := record(21)
	f.packet(1000000, tcp(1, 101, 24, payload))
	f.packet(2000000, tcp(1, 101, 24, payload))
	f.packet(3000000, tcp(1, 200, 24, payload))
	got := f.read(t, setupMetadata())
	row := got.Flows[0]
	if row.RawTCPPayloadBytes != uint64(3*len(payload)) || got.CoverageComplete || !contains(row.Issues, "tcp_reassembly_gap") {
		t.Fatal("raw counting or strict gap failed", row.RawTCPPayloadBytes, row.Issues)
	}
}

func TestNoExplicitMeasurementNeverWaivesMissingAnchor(t *testing.T) {
	f := newFixture(true)
	f.packet(1000, tcp(1, 100, 2, nil))
	got := f.read(t, metadata())
	if got.CoverageComplete || got.ZeroPayloadSetupOnly || !contains(got.GlobalReasons, "no_tls23_group_anchor") {
		t.Fatal("implicit no activity accepted")
	}
}

func TestHeaderCoverageContractAndOrderingPinned(t *testing.T) {
	raw, err := os.ReadFile("coverage-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err = json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(compact.Bytes())
	if hex.EncodeToString(sum[:]) != CoverageSemanticsSHA {
		t.Fatal("coverage contract SHA mismatch")
	}
	if OrderingSemanticsSHA != "3bedeecc9596777cf4f858748590a9c3b0380bc78b84de0518fd7a051972ca42" {
		t.Fatal("ordering semantics changed")
	}
}

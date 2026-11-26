package main

import (
	"testing"
	"time"
)

func TestUnsampledPrimaryFaultsAreUnknownWithoutErasingEarlierEvidence(t *testing.T) {
	for _, mode := range []string{"gap", "overlap_conflict", "malformed", "partial_header_without_close", "zero_payload_stream_clock", "ACK_only_no_SYN", "conflicting_synack"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(true)
			f.syn()
			f.packet(int64(time.Second), tcp(1, 101, 24, record(21)))
			at := int64(3 * time.Second)
			hello := record(21)
			hello[0] = 22
			if mode == "ACK_only_no_SYN" {
				f.packet(at, isolatedAttemptPacket(1, 201, 16, nil))
			} else {
				f.packet(at, isolatedAttemptPacket(1, 200, 2, nil))
			}
			if mode != "zero_payload_stream_clock" && mode != "ACK_only_no_SYN" {
				f.packet(at+1000, isolatedAttemptPacket(-1, 500, 18, nil))
			}
			want := ""
			switch mode {
			case "gap":
				f.packet(at+2000, isolatedAttemptPacket(1, 205, 24, hello[4:]))
				want = "tcp_reassembly_gap"
			case "overlap_conflict":
				f.packet(at+2000, isolatedAttemptPacket(1, 205, 24, hello[4:]))
				conflict := append([]byte{}, hello[6:]...)
				conflict[0] ^= 255
				f.packet(at+3000, isolatedAttemptPacket(1, 207, 24, conflict))
				want = "tcp_overlap_conflict"
			case "malformed":
				hello[0] = 99
				f.packet(at+2000, isolatedAttemptPacket(1, 201, 24, hello))
				want = "malformed_tls"
			case "partial_header_without_close":
				f.packet(at+2000, isolatedAttemptPacket(1, 201, 24, hello[:4]))
				want = "partial_final_tls_header"
			case "zero_payload_stream_clock":
				f.packet(at+3000, isolatedAttemptPacket(1, 201, 16, nil))
				f.packet(at+2000, isolatedAttemptPacket(1, 201, 16, nil))
				want = "non_monotonic_stream_clock"
			case "ACK_only_no_SYN":
				want = "missing_syn"
			case "conflicting_synack":
				f.packet(at+2000, isolatedAttemptPacket(-1, 600, 18, nil))
				want = "conflicting_syn_ack"
			}
			if mode != "partial_header_without_close" {
				f.packet(int64(4*time.Second), isolatedAttemptPacket(-1, 0, 20, nil))
			}
			// A different primary flow remains open into grace. A closed short partial
			// record must be timestamped at its close, not this global last packet.
			f.packet(int64(46*time.Second), tcp(1, 127, 16, nil))
			got := f.read(t, setupMetadata())
			if got.CoverageComplete || !contains(got.GlobalReasons, "primary_flow_fault: "+want) {
				t.Fatal("unsampled primary fault escaped whole-group QC", mode, got.GlobalReasons)
			}
			if got.Flows[1].First != nil {
				t.Fatal("fixture accidentally created a TLS23 prefix")
			}
			for _, w := range got.Flows[1].Windows {
				if mode != "partial_header_without_close" && w.Status != "not_applicable" {
					t.Fatal("fixture did not avoid all fixed windows")
				}
			}
			if !got.GroupWindows[0].Eligible {
				t.Fatal("known later fault erased earlier valid window")
			}
			for _, w := range got.Flows[0].Windows {
				if !w.Eligible {
					t.Fatal("independent healthy flow was erased")
				}
			}
		})
	}
}

func TestPostPrimaryFaultsDoNotCreateNewObligations(t *testing.T) {
	for _, mode := range []string{"malformed", "stream_clock"} {
		f := newFixture(true)
		f.syn()
		f.packet(int64(time.Second), tcp(1, 101, 24, record(21)))
		at := int64(46 * time.Second)
		if mode == "malformed" {
			bad := record(21)
			bad[0] = 99
			f.packet(at, tcp(1, 127, 24, bad))
		} else {
			f.packet(at+3000, tcp(1, 127, 16, nil))
			f.packet(at+2000, tcp(1, 127, 16, nil))
		}
		got := f.read(t, setupMetadata())
		if !got.CoverageComplete {
			t.Fatal("postprimary fault created a new obligation", mode, got.GlobalReasons)
		}
		if len(got.Flows[0].Issues) == 0 {
			t.Fatal("late fault diagnostic was discarded")
		}
	}
}

func TestRepeatedCausalFaultKeepsEarliestRawOccurrence(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(int64(time.Second), tcp(1, 101, 24, record(21)))
	// First reported stream-clock fault is in grace; a later file packet proves
	// the same fault inside primary. Retaining only first file occurrence is wrong.
	f.packet(int64(46*time.Second)+3000, tcp(1, 127, 16, nil))
	f.packet(int64(46*time.Second)+2000, tcp(1, 127, 16, nil))
	f.packet(int64(44*time.Second), tcp(1, 127, 16, nil))
	got := f.read(t, setupMetadata())
	if got.CoverageComplete || !contains(got.GlobalReasons, "primary_flow_fault: non_monotonic_stream_clock") {
		t.Fatal("primary fault hidden behind earlier file-order grace fault", got.GlobalReasons)
	}
	if !got.GroupWindows[0].Eligible {
		t.Fatal("earlier evidence was erased")
	}
}

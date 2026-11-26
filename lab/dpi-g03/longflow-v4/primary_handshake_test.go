package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func isolatedAttemptPacket(direction int, seq uint32, flags byte, payload []byte) []byte {
	p := tcp(direction, seq, flags, payload)
	if direction == 1 {
		binary.BigEndian.PutUint16(p[34:36], 30001)
	} else {
		binary.BigEndian.PutUint16(p[36:38], 30001)
	}
	return p
}

func TestUnsampledPrimaryPayloadMissingHandshakeInvalidatesWholeGroup(t *testing.T) {
	for _, mode := range []string{"clienthello_no_synack", "TFO_clienthello_no_synack", "ack_without_synack", "payload_without_initial_syn", "synack_without_initial_syn"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(true)
			f.syn()
			f.packet(int64(time.Second), tcp(1, 101, 24, record(21)))
			hello := record(21)
			hello[0] = 22
			at := int64(3 * time.Second)
			switch mode {
			case "TFO_clienthello_no_synack":
				f.packet(at, isolatedAttemptPacket(1, 200, 2, hello))
			case "payload_without_initial_syn":
				f.packet(at, isolatedAttemptPacket(1, 201, 24, hello))
			case "synack_without_initial_syn":
				f.packet(at, isolatedAttemptPacket(-1, 500, 18, nil))
				f.packet(at+2000, isolatedAttemptPacket(1, 201, 24, hello))
			default:
				f.packet(at, isolatedAttemptPacket(1, 200, 2, nil))
				if mode == "ack_without_synack" {
					f.packet(at+1000, isolatedAttemptPacket(-1, 500, 16, nil))
				}
				f.packet(at+2000, isolatedAttemptPacket(1, 201, 24, hello))
			}
			f.packet(int64(4*time.Second), isolatedAttemptPacket(-1, 0, 20, nil))
			got := f.read(t, setupMetadata())
			if got.CoverageComplete || !contains(got.GlobalReasons, "primary_payload_with_missing_handshake") {
				t.Fatalf("unsampled physical payload escaped: %s %+v", mode, got.GlobalReasons)
			}
			if len(got.Flows) != 2 || got.Flows[1].First != nil || got.Flows[1].RawTCPPayloadBytes != uint64(len(hello)) || !got.Flows[1].PrimaryScope {
				t.Fatal("fixture lost noTLS23 payload attempt")
			}
			for _, w := range got.Flows[1].Windows {
				if w.Status != "not_applicable" {
					t.Fatal("attempt was not wholly between sampled windows")
				}
			}
			if !got.GroupWindows[0].Eligible {
				t.Fatal("later fault erased sound earlier window")
			}
			for _, w := range got.Flows[0].Windows {
				if !w.Eligible {
					t.Fatal("later independent flow fault erased healthy flow observations")
				}
			}
		})
	}
}

func TestGraceOnlyMissingHandshakePayloadIsNotNewPrimaryObligation(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(int64(time.Second), tcp(1, 101, 24, record(21)))
	hello := record(21)
	hello[0] = 22
	f.packet(int64(46*time.Second), isolatedAttemptPacket(1, 200, 2, hello))
	f.packet(int64(46*time.Second)+1000, isolatedAttemptPacket(-1, 0, 20, nil))
	got := f.read(t, setupMetadata())
	if !got.CoverageComplete || contains(got.GlobalReasons, "primary_payload_with_missing_handshake") || got.Flows[1].PrimaryScope {
		t.Fatal("grace-only payload created primary obligation", got.GlobalReasons)
	}
}

func TestUnsampledPureSYNAndCapturedHandshakeRetainCoverage(t *testing.T) {
	for _, withPayload := range []bool{false, true} {
		f := newFixture(true)
		f.syn()
		f.packet(int64(time.Second), tcp(1, 101, 24, record(21)))
		f.packet(int64(3*time.Second), isolatedAttemptPacket(1, 200, 2, nil))
		if withPayload {
			hello := record(21)
			hello[0] = 22
			f.packet(int64(3*time.Second)+1000, isolatedAttemptPacket(-1, 500, 18, nil))
			f.packet(int64(3*time.Second)+2000, isolatedAttemptPacket(1, 201, 24, hello))
		}
		f.packet(int64(4*time.Second), isolatedAttemptPacket(-1, 0, 20, nil))
		got := f.read(t, setupMetadata())
		if !got.CoverageComplete {
			t.Fatal("zero-payload or valid handshake regressed", withPayload, got.GlobalReasons)
		}
	}
}

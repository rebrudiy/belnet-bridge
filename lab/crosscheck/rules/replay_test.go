package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifierControls(t *testing.T) {
	// Real captured introduction, not a made-up classifier-positive byte array.
	fixture, err := os.ReadFile("../../../internal/iwpdetector/testdata/intro.bin")
	if err != nil {
		t.Fatal(err)
	}
	keys := loadKeys("../../../lab/results/20261119T025447Z-control/public-identities.txt")
	if len(keys) != 6 {
		t.Fatal("missing public identity set")
	}
	crypto := fresh(modes[2], keys)
	if drop, reason := crypto.classify(udpPacket(fixture, netip.MustParseAddr("203.0.113.10"))); !drop || reason != "crypto" {
		t.Fatalf("real introduction was not recognized: %v %q", drop, reason)
	}
	// The recorded implementation intentionally ignores TCP, even to a listed IP.
	tcp := make([]byte, 40)
	tcp[0] = 0x45
	tcp[9] = 6
	copy(tcp[12:16], []byte{10, 100, 0, 20})
	copy(tcp[16:20], []byte{10, 88, 0, 12})
	binary.BigEndian.PutUint16(tcp[22:24], 443)
	for _, m := range modes {
		if drop, reason := fresh(m, keys).classify(tcp); drop {
			t.Fatalf("TCP should pass %s: %s", m.Name, reason)
		}
	}
}

func TestPCAPReaderClassifiesActualEthernetPayload(t *testing.T) {
	packet := append(make([]byte, 14), udpPacket([]byte("ordinary echo"), netip.MustParseAddr("10.88.0.12"))...)
	packet[12] = 8
	packet[13] = 0
	hdr := make([]byte, 24)
	copy(hdr, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(packet)))
	path := filepath.Join(t.TempDir(), "control.pcap")
	data := append(append(hdr, rec...), packet...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	result := replay(path, nil)
	if result.IPv4 != 1 || result.UDP != 1 || result.Verdicts[modes[0].Name].Dropped != 1 {
		t.Fatalf("capture reader skipped or misclassified payload: %+v", result)
	}
}

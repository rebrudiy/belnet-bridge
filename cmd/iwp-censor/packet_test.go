package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/rebrudiy/belnet-bridge/internal/iwpdetector"
)

func TestCapturedIntroThroughIPv4Parser(t *testing.T) {
	intro, err := os.ReadFile("../../internal/iwpdetector/testdata/intro.bin")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.ReadFile("../../internal/iwpdetector/testdata/identity.hex")
	if err != nil {
		t.Fatal(err)
	}
	key, err := iwpdetector.ParseIdentity(string(identity))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := iwpdetector.New([][]byte{key})
	p := make([]byte, 28+len(intro))
	p[0] = 0x45
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(intro)))
	copy(p[28:], intro)
	if matched, _ := d.Match(udpPayload(p)); !matched {
		t.Fatal("real introduction not detected")
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0x65 }, func(p []byte) { p[0] = 0x4f },
		func(p []byte) { p[9] = 6 }, func(p []byte) { p[6] = 0x20 },
		func(p []byte) { p[7] = 1 }, func(p []byte) { p[25] = 7 },
	} {
		bad := bytes.Clone(p)
		mutate(bad)
		if udpPayload(bad) != nil {
			t.Fatal("accepted malformed, fragmented, or non-UDP packet")
		}
	}
	for n := 0; n < len(p); n++ {
		if udpPayload(p[:n]) != nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}

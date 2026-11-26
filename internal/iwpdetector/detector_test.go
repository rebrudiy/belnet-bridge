package iwpdetector

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func makeIntro(t *testing.T, identity []byte) []byte {
	t.Helper()
	payload := make([]byte, introSize)
	for i := tagSize; i < len(payload); i++ {
		payload[i] = byte(i*37 + 11)
	}
	key := blake2b.Sum256(identity)
	h, err := blake2b.New256(key[:])
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.Write(payload[tagSize:])
	copy(payload, h.Sum(nil))
	return payload
}

func newDetector(t *testing.T, identities ...[]byte) *Detector {
	t.Helper()
	d, err := New(identities)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestConstructedIntro(t *testing.T) {
	identity := bytes.Repeat([]byte{0x41}, identitySize)
	other := bytes.Repeat([]byte{0x42}, identitySize)
	d := newDetector(t, other, identity)
	payload := makeIntro(t, identity)
	if matched, got := d.Match(payload); !matched || got != hex.EncodeToString(identity) {
		t.Fatalf("Match = (%v, %q), want matching recipient identity", matched, got)
	}
	if matched, got := newDetector(t, other).Match(payload); matched || got != "" {
		t.Fatalf("unknown identity matched: (%v, %q)", matched, got)
	}

	for _, offset := range []int{0, 31, 32, 63, 64, 223} {
		tampered := bytes.Clone(payload)
		tampered[offset] ^= 1
		if matched, got := d.Match(tampered); matched || got != "" {
			t.Errorf("tampered byte %d matched: (%v, %q)", offset, matched, got)
		}
	}
	for _, size := range []int{0, 31, 32, 64, 223, 225, 2048} {
		wrongSize := append(bytes.Clone(payload), make([]byte, 2048)...)[:size]
		if matched, got := d.Match(wrongSize); matched || got != "" {
			t.Errorf("length %d matched: (%v, %q)", size, matched, got)
		}
	}

	// New copies/derives its state instead of retaining caller-owned key bytes.
	identity[0] ^= 1
	if matched, _ := d.Match(payload); !matched {
		t.Fatal("caller identity mutation changed detector")
	}
}

func TestActualBelNetCapture(t *testing.T) {
	payload, err := os.ReadFile("testdata/intro.bin")
	if err != nil {
		t.Fatal(err)
	}
	identityHex, err := os.ReadFile("testdata/identity.hex")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ParseIdentity(string(identityHex))
	if err != nil {
		t.Fatal(err)
	}
	d := newDetector(t, make([]byte, identitySize), identity)
	if matched, got := d.Match(payload); !matched || got != strings.TrimSpace(string(identityHex)) {
		t.Fatalf("real IWP introduction: Match = (%v, %q)", matched, got)
	}
	before := bytes.Clone(payload)
	_, _ = d.Match(payload)
	if !bytes.Equal(payload, before) {
		t.Fatal("Match modified input payload")
	}
}

func TestNonIWPInputs(t *testing.T) {
	d := newDetector(t, bytes.Repeat([]byte{0x41}, identitySize), bytes.Repeat([]byte{0x42}, identitySize))
	rng := rand.New(rand.NewSource(20261119))
	payload := make([]byte, introSize)
	for i := range 4096 {
		_, _ = rng.Read(payload)
		if matched, _ := d.Match(payload); matched {
			t.Fatalf("deterministic random payload %d matched", i)
		}
	}
	for _, value := range []byte{0, 0xff} {
		if matched, _ := d.Match(bytes.Repeat([]byte{value}, introSize)); matched {
			t.Fatalf("constant payload %x matched", value)
		}
	}
	// This is only a regression check; random payloads are not a benign traffic corpus.
}

func TestNewValidation(t *testing.T) {
	for _, identities := range [][][]byte{nil, {}, {nil}, {make([]byte, 31)}, {make([]byte, 33)}, {make([]byte, 32), {}}} {
		if d, err := New(identities); err == nil || d != nil {
			t.Errorf("New(%v): got (%v, %v), want error", identities, d, err)
		}
	}
}

func TestParseIdentity(t *testing.T) {
	identity := bytes.Repeat([]byte{0x91}, identitySize)
	address := zbase32.EncodeToString(identity) + ".mnode"
	for _, text := range []string{hex.EncodeToString(identity), strings.ToUpper(hex.EncodeToString(identity)), address, " \n" + strings.ToUpper(address) + "\t"} {
		got, err := ParseIdentity(text)
		if err != nil || !bytes.Equal(got, identity) {
			t.Errorf("ParseIdentity(%q) = (%x, %v)", text, got, err)
		}
	}
	for _, text := range []string{"", "abcd", strings.Repeat("g", 64), strings.TrimSuffix(address, ".mnode"), address + ".evil", strings.Repeat("y", 51) + "b.mnode", strings.Repeat("y", 53) + ".mnode"} {
		if got, err := ParseIdentity(text); err == nil || got != nil {
			t.Errorf("invalid ParseIdentity(%q) = (%x, %v)", text, got, err)
		}
	}
}

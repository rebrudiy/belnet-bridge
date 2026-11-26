package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBurstMatchesIndependentGolden(t *testing.T) {
	r := httptest.NewRequest("GET", "https://decoy.test/burst?nonce="+strings.Repeat("a", 64), nil)
	w := httptest.NewRecorder()
	burst(w, r)
	if w.Code != 200 || w.Body.Len() != burstSize {
		t.Fatal("bad fixture size/status")
	}
	sum := sha256.Sum256(w.Body.Bytes())
	if hex.EncodeToString(sum[:]) != "f4880c0c720e714910e28f2a004ab79462f8f30788d73947083381ce94304662" {
		t.Fatal("server pattern differs from independent Node periodic golden")
	}
}
func TestBurstRejectsMissingNonce(t *testing.T) {
	w := httptest.NewRecorder()
	burst(w, httptest.NewRequest("GET", "/burst", nil))
	if w.Code != 400 {
		t.Fatal("unbounded request accepted")
	}
}

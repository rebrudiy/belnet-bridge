package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// chanDev is an in-memory TUN: tests push packets into in and read what the code wrote from out.
type chanDev struct {
	in, out chan []byte
}

func newChanDev() *chanDev { return &chanDev{in: make(chan []byte, 16), out: make(chan []byte, 16)} }

func (d *chanDev) Read(p []byte) (int, error) {
	pkt, ok := <-d.in
	if !ok {
		return 0, io.EOF
	}
	return copy(p, pkt), nil
}

func (d *chanDev) Write(p []byte) (int, error) {
	d.out <- append([]byte(nil), p...)
	return len(p), nil
}

func (d *chanDev) Close() error { close(d.in); return nil }

// ipv4 builds a minimal IPv4 header (no checksum, nothing validates it here) plus payload.
func ipv4(src, dst string, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)
	return pkt
}

func recv(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packet")
		return nil
	}
}

func TestBridgeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDev := newChanDev()
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "It works!") })
	srv := NewServer(serverDev, NewIPPool(netip.MustParsePrefix("10.77.0.0/24")), "/ws", "s3cret", cover)
	go srv.RouteFromDevice(ctx)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	wsURL := "ws" + strings.TrimPrefix(hs.URL, "http") + "/ws"

	ws, addr, gw, err := Dial(ctx, wsURL, "s3cret", hs.Client())
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "10.77.0.2/24" || gw.String() != "10.77.0.1" {
		t.Fatalf("got address %s gateway %s", addr, gw)
	}
	clientDev := newChanDev()
	go Relay(ctx, clientDev, ws)

	// outbound: client app -> client TUN -> bridge -> server TUN
	out := ipv4("10.77.0.2", "203.0.113.5", "llarp-out")
	clientDev.in <- out
	if got := recv(t, serverDev.out); string(got[20:]) != "llarp-out" {
		t.Fatalf("server got %q", got[20:])
	}

	// spoofed source addresses are dropped
	clientDev.in <- ipv4("10.77.0.99", "203.0.113.5", "spoof")
	clientDev.in <- ipv4("10.77.0.2", "203.0.113.5", "after-spoof")
	if got := recv(t, serverDev.out); string(got[20:]) != "after-spoof" {
		t.Fatalf("spoofed packet was forwarded: %q", got[20:])
	}

	// inbound: internet -> server TUN -> bridge -> client TUN
	serverDev.in <- ipv4("203.0.113.5", "10.77.0.2", "llarp-in")
	if got := recv(t, clientDev.out); string(got[20:]) != "llarp-in" {
		t.Fatalf("client got %q", got[20:])
	}
}

func TestCoverPageForStrangers(t *testing.T) {
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "It works!") })
	srv := NewServer(newChanDev(), NewIPPool(netip.MustParsePrefix("10.77.0.0/24")), "/ws", "s3cret", cover)
	for _, req := range []*http.Request{
		httptest.NewRequest("GET", "/", nil),
		httptest.NewRequest("GET", "/ws", nil), // right path, no token
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Body.String() != "It works!" {
			t.Errorf("%s: got %q, want cover page", req.URL, rec.Body.String())
		}
	}
	bad := httptest.NewRequest("GET", "/ws", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, bad)
	if rec.Body.String() != "It works!" {
		t.Error("wrong token should get the cover page")
	}
}

func TestIPPool(t *testing.T) {
	p := NewIPPool(netip.MustParsePrefix("10.0.0.0/30")) // .1 gateway, .2 only client, .3 broadcast
	a, err := p.Acquire()
	if err != nil || a.String() != "10.0.0.2" {
		t.Fatalf("Acquire = %s, %v", a, err)
	}
	if _, err := p.Acquire(); err == nil {
		t.Fatal("pool should be exhausted")
	}
	p.Release(a)
	if b, err := p.Acquire(); err != nil || b != a {
		t.Fatalf("after release: %s, %v", b, err)
	}
}

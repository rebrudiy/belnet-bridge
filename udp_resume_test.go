package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/shaping"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

func TestVersion2RetainsIWPAddressAcrossTLSReconnect(t *testing.T) {
	target := udpSocket(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxUDPDatagram)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			target.WriteToUDP(fmt.Appendf(nil, "%d:%s", addr.Port, buf[:n]), addr)
		}
	}()
	defer func() { target.Close(); <-done }()
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "secret", "/ws", 8)
	defer bridge.Close()
	server := httptest.NewTLSServer(bridge)
	defer server.Close()
	endpoint := "wss" + strings.TrimPrefix(server.URL, "https") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	profile := shaping.Profile{Name: "test", Up: shaping.Policy{PadTo: 128}, Down: shaping.Policy{PadTo: 256, WarmupFrames: 2, DummyBytes: 128}}
	dial := func(sid string) *websocket.Conn {
		headers, err := wireconfig.Headers("secret", sid, profile, "/ws")
		if err != nil {
			t.Fatal(err)
		}
		ws, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: headers})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ws.CloseNow() })
		return ws
	}
	exchange := func(ws *websocket.Conn, payload string) string {
		frame, err := shaping.Encode([][]byte{[]byte(payload)}, profile.Up, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageBinary, frame); err != nil {
			t.Fatal(err)
		}
		for {
			_, frame, err := ws.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			packets, err := shaping.Decode(frame)
			if err != nil {
				t.Fatal(err)
			}
			if len(packets) == 0 {
				continue
			}
			port, got, ok := strings.Cut(string(packets[0]), ":")
			if !ok || got != payload {
				t.Fatal("datagram corrupted")
			}
			return port
		}
	}
	sid := strings.Repeat("a", 64)
	first := dial(sid)
	port := exchange(first, "before")
	// A new connection replaces an old active attachment, without a new UDP port.
	second := dial(sid)
	if got := exchange(second, "after"); got != port {
		t.Fatalf("IWP address changed: %s -> %s", port, got)
	}
	third := dial(strings.Repeat("b", 64))
	if got := exchange(third, "other-client"); got == port {
		t.Fatal("distinct sessions shared a UDP address")
	}
}

func TestRetainedUDPFailedUpgradeReleasesLease(t *testing.T) {
	target := udpSocket(t)
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "secret", "/ws", 8)
	defer bridge.Close()
	sid := strings.Repeat("c", 64)
	headers, err := wireconfig.Headers("secret", sid, shaping.Profile{Name: "test"}, "/ws")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/ws", nil)
	request.Header = headers // Deliberately omit the WebSocket upgrade headers.
	response := httptest.NewRecorder()
	bridge.ServeHTTP(response, request)
	if response.Code == http.StatusSwitchingProtocols {
		t.Fatal("invalid upgrade succeeded")
	}
	bridge.sessionsMu.Lock()
	defer bridge.sessionsMu.Unlock()
	if p := bridge.sessions[sid]; p == nil || p.active != 0 {
		t.Fatal("failed upgrade leaked an active UDP lease")
	}
}

func TestRetainedUDPLeaseReleaseRenewsIdleLifetime(t *testing.T) {
	target := udpSocket(t)
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "secret", "/ws", 8)
	defer bridge.Close()
	p, err := bridge.resumed("session")
	if err != nil {
		t.Fatal(err)
	}
	bridge.sessionsMu.Lock()
	p.last = time.Now().Add(-2 * resumeLifetime)
	bridge.sessionsMu.Unlock()
	bridge.releaseResumed(p)
	resumed, err := bridge.resumed("session")
	if err != nil {
		t.Fatal(err)
	}
	if resumed != p {
		t.Fatal("attachment release did not renew the UDP association lifetime")
	}
	bridge.releaseResumed(resumed)
	bridge.sessionsMu.Lock()
	p.last = time.Now().Add(-2 * resumeLifetime)
	bridge.sessionsMu.Unlock()
	replacement, err := bridge.resumed("session")
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.releaseResumed(replacement)
	if replacement == p {
		t.Fatal("expired inactive association was retained")
	}
}

func TestRetainedUDPRejectsClosedSocketAndKeepsActiveSocket(t *testing.T) {
	target := udpSocket(t)
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "secret", "/ws", 8)
	defer bridge.Close()
	p, err := bridge.resumed("closed")
	if err != nil {
		t.Fatal(err)
	}
	bridge.releaseResumed(p)
	p.close()
	replacement, err := bridge.resumed("closed")
	if err != nil {
		t.Fatal(err)
	}
	if replacement == p {
		t.Fatal("returned a dead UDP association")
	}
	defer bridge.releaseResumed(replacement)
	active, err := bridge.resumed("active")
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.releaseResumed(active)
	bridge.sessionsMu.Lock()
	active.last = time.Now().Add(-2 * resumeLifetime)
	bridge.sessionsMu.Unlock()
	trigger, err := bridge.resumed("trigger-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.releaseResumed(trigger)
	select {
	case <-active.closed:
		t.Fatal("expired an attached downlink-only session")
	default:
	}
}

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestUDPClientRejectsMalformedProfileFile(t *testing.T) {
	for _, input := range []string{
		`{"name":"selected"} {}`,
		`{"name":"selected","unknown":true}`,
		`{"name":"selected"}` + strings.Repeat(" ", 8192) + `{}`,
	} {
		path := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if err := runUDPClient([]string{"-listen", "127.0.0.1:0", "-url", "wss://127.0.0.1/ws", "-token", "secret", "-profile", path}); err == nil {
			t.Fatal("malformed profile was accepted")
		}
	}
}

func TestUDPTransportTLSAndPeerIsolation(t *testing.T) {
	target := udpSocket(t)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, maxUDPDatagram)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			response := fmt.Appendf(nil, "%d:", addr.Port)
			response = append(response, buf[:n]...)
			target.WriteToUDP(response, addr)
		}
	}()
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "test-token", "/private", 8)
	https := httptest.NewTLSServer(bridge)
	defer https.Close()
	ctx, cancel := context.WithCancel(context.Background())
	proxy := udpSocket(t)
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- RunUDPProxy(ctx, proxy, "wss"+strings.TrimPrefix(https.URL, "https")+"/private", "test-token", https.Client())
	}()
	defer func() {
		cancel()
		select {
		case err := <-proxyDone:
			if err != nil {
				t.Errorf("proxy shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy failed to stop active sessions")
		}
		target.Close()
		<-echoDone
	}()

	ports := make(map[string]bool)
	for _, payload := range []string{"first-client", strings.Repeat("b", 4096)} {
		peer := udpSocket(t)
		peer.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := peer.WriteToUDP([]byte(payload), proxy.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8192)
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		port, got, ok := strings.Cut(string(buf[:n]), ":")
		if !ok || got != payload {
			t.Fatal("datagram boundary or payload changed")
		}
		if ports[port] {
			t.Fatal("different UDP clients shared the same IWP-side socket")
		}
		ports[port] = true
	}
}

func TestUDPTransportRejectsBadTokenAndUntrustedTLS(t *testing.T) {
	target := udpSocket(t)
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "valid", "/private", 1)
	https := httptest.NewTLSServer(bridge)
	defer https.Close()
	url := "wss" + strings.TrimPrefix(https.URL, "https") + "/private"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, token := range []string{"", "wrong"} {
		ws, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{
			HTTPClient: https.Client(), HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
		})
		if ws != nil {
			ws.CloseNow()
		}
		if err == nil || resp == nil || resp.StatusCode != http.StatusOK {
			t.Fatal("invalid credential did not receive the ordinary cover page")
		}
		if len(bridge.slots) != 0 {
			t.Fatal("unauthorized request acquired a UDP session")
		}
	}
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPClient: &http.Client{}, HTTPHeader: http.Header{"Authorization": {"Bearer valid"}},
	})
	if ws != nil {
		ws.CloseNow()
	}
	if err == nil {
		t.Fatal("an untrusted test certificate was accepted")
	}
}

func TestUDPTransportRejectsCleartextURL(t *testing.T) {
	for _, endpoint := range []string{"ws://127.0.0.1/ws", "http://127.0.0.1/ws", "wss://user:password@example.com/ws"} {
		if err := RunUDPProxy(context.Background(), udpSocket(t), endpoint, "secret", nil); err == nil {
			t.Fatalf("accepted insecure or ambiguous URL %s", endpoint)
		}
	}
}

func TestUDPTransportDoesNotFollowRedirect(t *testing.T) {
	redirected := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected <- r.Header.Get("Authorization")
	}))
	defer target.Close()
	requested := make(chan struct{}, 1)
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		select {
		case requested <- struct{}{}:
		default:
		}
	}))
	defer front.Close()
	ctx, cancel := context.WithCancel(context.Background())
	proxy := udpSocket(t)
	done := make(chan error, 1)
	go func() {
		done <- RunUDPProxy(ctx, proxy, "wss"+strings.TrimPrefix(front.URL, "https"), "secret", front.Client())
	}()
	peer := udpSocket(t)
	peer.WriteToUDP([]byte("datagram"), proxy.LocalAddr().(*net.UDPAddr))
	select {
	case <-requested:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("HTTPS endpoint was not contacted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not stop")
	}
	select {
	case token := <-redirected:
		t.Fatalf("followed a redirect and disclosed %q", token)
	default:
	}
}

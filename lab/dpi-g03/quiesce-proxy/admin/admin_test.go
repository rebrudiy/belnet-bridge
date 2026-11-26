package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rebrudiy/belnet-bridge/g03controls/connectproxy"
)

type publicResolver struct{}

func (publicResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
}
func TestControlBindMustBeLiteralLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8091", "127.0.0.2:8091", "[::1]:8091"} {
		if e := ValidateControlAddress(address); e != nil {
			t.Fatal(address, e)
		}
	}
	for _, address := range []string{"0.0.0.0:8091", "10.88.0.11:8091", "[::]:8091", "localhost:8091", "127.0.0.1:0", "127.0.0.1:99999", "127.0.0.1:08091", "127.0.0.1"} {
		if e := ValidateControlAddress(address); e == nil {
			t.Fatalf("unsafe control bind accepted: %s", address)
		}
	}
}
func TestAdminRejectsNonloopbackAndWrongMethods(t *testing.T) {
	c := New()
	for _, tc := range []struct {
		method, path, remote string
		status               int
	}{{"GET", "/state", "203.0.113.2:8091", 403}, {"POST", "/quiesce", "10.88.0.2:8091", 403}, {"GET", "/quiesce", "127.0.0.1:1234", 405}, {"POST", "/state", "[::1]:1234", 405}, {"GET", "/other", "127.0.0.1:1234", 404}} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = tc.remote
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(tc, w.Code)
		}
	}
}
func TestQuiesceClosesActiveTCPTunnelDeniesNewAndKeepsServersAlive(t *testing.T) {
	// Actual bounded localhost TCP sockets exercise EOF and listener lifecycle;
	// this is a unit fixture, never public/lab acquisition.
	upstream, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer upstream.Close()
	peerReady := make(chan net.Conn, 1)
	go func() {
		peer, e := upstream.Accept()
		if e == nil {
			peerReady <- peer
		}
	}()
	cfg := connectproxy.Config{GroupID: "unit-only", PublicAuthorities: []string{"example.test:443"}, MaxConnections: 2, DialTimeoutMS: 1000, MaxTunnelMS: 3000}
	controller := New()
	proxy, e := connectproxy.NewWithIO(cfg, publicResolver{}, func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", upstream.Addr().String())
	}, controller.NoteEvent)
	if e != nil {
		t.Fatal(e)
	}
	controller.Bind(proxy)
	proxyHTTP := httptest.NewServer(proxy)
	defer proxyHTTP.Close()
	adminHTTP := httptest.NewServer(controller)
	defer adminHTTP.Close()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = proxy.Shutdown(ctx)
	}()
	client, e := net.DialTimeout("tcp4", strings.TrimPrefix(proxyHTTP.URL, "http://"), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, e = fmt.Fprint(client, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	if e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(client)
	response, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || response.StatusCode != 200 {
		t.Fatal("CONNECT failed", e)
	}
	var peer net.Conn
	select {
	case peer = <-peerReady:
		defer peer.Close()
	case <-time.After(time.Second):
		t.Fatal("upstream not accepted")
	}
	if _, e = peer.Write([]byte("independent-server-message")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len("independent-server-message"))
	if _, e = io.ReadFull(reader, b); e != nil {
		t.Fatal(e)
	}
	httpClient := &http.Client{Timeout: time.Second}
	resultResponse, e := httpClient.Post(adminHTTP.URL+"/quiesce", "application/json", nil)
	if e != nil {
		t.Fatal(e)
	}
	var result Result
	e = json.NewDecoder(resultResponse.Body).Decode(&result)
	resultResponse.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	if resultResponse.StatusCode != 200 || result.Result != "ok" || result.AcceptedTunnelsClosed != 1 || result.AcceptedTunnelsClosedTotal != 1 || result.FinishedUnixMicros < result.StartedUnixMicros {
		t.Fatalf("bad quiesce result: %+v", result)
	}
	if _, e = reader.ReadByte(); e != io.EOF {
		t.Fatal("active tunnel did not EOF after quiesce", e)
	}
	// The public listener and namespace-owner process must remain up: new CONNECT
	// receives a real503 instead of connection refused due to process shutdown.
	next, e := net.DialTimeout("tcp4", strings.TrimPrefix(proxyHTTP.URL, "http://"), time.Second)
	if e != nil {
		t.Fatal("proxy listener stopped", e)
	}
	defer next.Close()
	_ = next.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprint(next, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	denied, e := http.ReadResponse(bufio.NewReader(next), &http.Request{Method: "CONNECT"})
	if e != nil || denied.StatusCode != 503 {
		t.Fatal("new CONNECT was not permanently denied", e)
	}
	denied.Body.Close()
	stateResponse, e := httpClient.Get(adminHTTP.URL + "/state")
	if e != nil {
		t.Fatal("admin listener stopped", e)
	}
	var s struct {
		Quiesced  bool `json:"quiesced"`
		Completed bool `json:"shutdown_completed"`
	}
	e = json.NewDecoder(stateResponse.Body).Decode(&s)
	stateResponse.Body.Close()
	if e != nil || !s.Quiesced || !s.Completed {
		t.Fatal("state not quiesced/completed", s, e)
	}
	again := controller.Quiesce()
	if again != result {
		t.Fatal("quiesce not idempotent")
	}
}

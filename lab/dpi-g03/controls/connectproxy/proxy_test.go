package connectproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureResolver struct {
	ips     []netip.Addr
	calls   int
	network string
}

func (r *fixtureResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	r.network = network
	return r.ips, nil
}
func config() Config {
	return Config{GroupID: "unit", PublicAuthorities: []string{"example.test:443", "*.googlevideo.com:443"}, LabMappings: map[string]string{"bench.test:443": "10.88.0.11:20443"}, MaxConnections: 2, DialTimeoutMS: 100, MaxTunnelMS: 1000}
}
func TestIPv4PublicPolicy(t *testing.T) {
	for _, text := range []string{"127.0.0.1", "10.1.2.3", "100.64.1.2", "169.254.1.1", "198.18.0.1", "192.0.2.1", "224.0.0.1", "240.1.1.1", "::1", "::ffff:1.1.1.1"} {
		if PublicIPv4(netip.MustParseAddr(text)) {
			t.Fatalf("reserved/private address allowed: %s", text)
		}
	}
	if !PublicIPv4(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IPv4 rejected")
	}
}
func TestAllowlistAndResolutionNeverRedialsHostname(t *testing.T) {
	r := &fixtureResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("1.1.1.1")}}
	var address, network string
	p, e := NewWithIO(config(), r, func(_ context.Context, n, a string) (net.Conn, error) {
		network, address = n, a
		c, d := net.Pipe()
		d.Close()
		return c, nil
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	c, _, route, e := p.target(context.Background(), "example.test:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if r.calls != 1 || r.network != "ip4" || network != "tcp4" || address != "1.1.1.1:443" || route != "public" {
		t.Fatal("resolver/dial policy bypass")
	}
	r.calls = 0
	c, _, route, e = p.target(context.Background(), "bench.test:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if r.calls != 0 || address != "10.88.0.11:20443" || route != "lab" {
		t.Fatal("fixed mapping was not exact")
	}
	for _, authority := range []string{"evil.test:443", "example.test:80", "googlevideo.com:443", "rr.googlevideo.com.evil.test:443", "10.0.0.1:443", "example.test:443/path", "user@example.test:443"} {
		if _, _, _, e := p.target(context.Background(), authority); e == nil {
			t.Fatalf("denied authority accepted: %s", authority)
		}
	}
	if !matches("*.googlevideo.com:443", "rr1.googlevideo.com:443") {
		t.Fatal("declared subdomain wildcard rejected")
	}
}
func TestRejectsUnboundedConfiguration(t *testing.T) {
	for _, mutate := range []func(*Config){func(c *Config) { c.MaxConnections = 0 }, func(c *Config) { c.MaxTunnelMS = 180001 }, func(c *Config) { c.PublicAuthorities = []string{"*:443"} }, func(c *Config) { c.LabMappings["lab:443"] = "hostname:80" }} {
		c := config()
		mutate(&c)
		if _, e := New(c, nil); e == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

type hijackWriter struct {
	conn   net.Conn
	rw     *bufio.ReadWriter
	header http.Header
}

func (w *hijackWriter) Header() http.Header                          { return w.header }
func (w *hijackWriter) Write(p []byte) (int, error)                  { return len(p), nil }
func (w *hijackWriter) WriteHeader(int)                              {}
func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.conn, w.rw, nil }
func TestConnectPreservesBufferedTLSBytesAndShutdown(t *testing.T) {
	client, server := net.Pipe()
	upstream, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	var mu sync.Mutex
	events := []Event{}
	p, e := NewWithIO(config(), &fixtureResolver{}, func(context.Context, string, string) (net.Conn, error) { return upstream, nil }, func(event Event) { mu.Lock(); events = append(events, event); mu.Unlock() })
	if e != nil {
		t.Fatal(e)
	}
	w := &hijackWriter{conn: server, rw: bufio.NewReadWriter(bufio.NewReader(io.MultiReader(strings.NewReader("hello"), server)), bufio.NewWriter(server)), header: make(http.Header)}
	request := httptest.NewRequest("CONNECT", "http://bench.test:443", nil)
	request.URL.Host = "bench.test:443"
	finished := make(chan struct{})
	go func() { p.ServeHTTP(w, request); close(finished) }()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		buf := make([]byte, 5)
		_, err := io.ReadFull(remote, buf)
		if err != nil || string(buf) != "hello" {
			return
		}
		_, _ = remote.Write([]byte("world"))
	}()
	reader := bufio.NewReader(client)
	response, e := http.ReadResponse(reader, request)
	if e != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT response: %v", e)
	}
	got := make([]byte, 5)
	if _, e := io.ReadFull(reader, got); e != nil || string(got) != "world" {
		t.Fatalf("buffered input lost: %v", e)
	}
	<-peerDone
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := p.Shutdown(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("tunnel goroutines leaked")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || !events[0].Accepted || events[0].UpBytes != 5 || events[0].DownBytes != 5 {
		t.Fatalf("unexpected counters: %+v", events)
	}
}
func TestOrdinaryHTTPIsNotAnOpenForwardProxy(t *testing.T) {
	p, e := New(config(), nil)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "https://example.test/", nil))
	if w.Code != 405 {
		t.Fatal("non CONNECT accepted")
	}
}

func TestLabMappingsCannotOverridePublicTLSOrigins(t *testing.T) {
	c := config()
	c.LabMappings["www.google.com:443"] = "10.88.0.11:443"
	if _, e := New(c, nil); e == nil {
		t.Fatal("public origin silently remapped to lab SPKI")
	}
	c = config()
	c.LabMappings["lab.test:443"] = "127.0.0.1:80"
	if _, e := New(c, nil); e == nil {
		t.Fatal("lab mapping escaped explicit entry1/entry2 scope")
	}
}

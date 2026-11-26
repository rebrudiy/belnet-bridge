// Package connectproxy is a bounded, allowlisted TCP CONNECT relay, not a TLS MITM.
package connectproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	GroupID           string            `json:"group_id"`
	PublicAuthorities []string          `json:"public_authorities"`
	LabMappings       map[string]string `json:"lab_mappings"`
	MaxConnections    int               `json:"max_connections"`
	DialTimeoutMS     int               `json:"dial_timeout_ms"`
	MaxTunnelMS       int               `json:"max_tunnel_ms"`
}
type Event struct {
	ID                 uint64 `json:"id"`
	GroupID            string `json:"group_id"`
	Authority          string `json:"authority"`
	Route              string `json:"route"`
	DialAddress        string `json:"dial_address,omitempty"`
	UpstreamLocal      string `json:"upstream_local,omitempty"`
	UpstreamRemote     string `json:"upstream_remote,omitempty"`
	ClientRemote       string `json:"client_remote,omitempty"`
	StartedUnixMicros  int64  `json:"started_unix_micros"`
	FinishedUnixMicros int64  `json:"finished_unix_micros"`
	Accepted           bool   `json:"accepted"`
	UpBytes            int64  `json:"up_bytes"`
	DownBytes          int64  `json:"down_bytes"`
	ErrorKind          string `json:"error_kind,omitempty"`
}
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type DialFunc func(context.Context, string, string) (net.Conn, error)
type Proxy struct {
	config   Config
	resolver Resolver
	dial     DialFunc
	log      func(Event)
	ctx      context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	mu       sync.Mutex
	closed   bool
	active   map[net.Conn]struct{}
	wg       sync.WaitGroup
	next     atomic.Uint64
}

func New(config Config, logger func(Event)) (*Proxy, error) {
	return NewWithIO(config, net.DefaultResolver, (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext, logger)
}

// NewWithIO permits deterministic unit fixtures without opening public sockets.
func NewWithIO(config Config, resolver Resolver, dial DialFunc, logger func(Event)) (*Proxy, error) {
	if config.MaxConnections < 1 || config.MaxConnections > 64 || config.DialTimeoutMS < 1 || config.DialTimeoutMS > 10000 || config.MaxTunnelMS < 1 || config.MaxTunnelMS > 180000 || len(config.GroupID) > 128 || len(config.PublicAuthorities) > 128 || len(config.LabMappings) > 16 {
		return nil, errors.New("invalid bounded proxy configuration")
	}
	if resolver == nil || dial == nil {
		return nil, errors.New("resolver and dialer required")
	}
	mappings := make(map[string]string, len(config.LabMappings))
	for authority, target := range config.LabMappings {
		normal, labHost, _, err := parseAuthority(authority, false)
		if err != nil || normal != authority || (!strings.HasSuffix(labHost, ".test") && labHost != "10.88.0.11" && labHost != "10.88.0.12") {
			return nil, errors.New("lab mapping needs canonical exact authority")
		}
		ip, port, err := net.SplitHostPort(target)
		addr, parseErr := netip.ParseAddr(ip)
		if err != nil || parseErr != nil || !addr.Is4() || (addr.String() != "10.88.0.11" && addr.String() != "10.88.0.12") || !validPort(port) {
			return nil, errors.New("lab target needs literal IPv4:port")
		}
		mappings[authority] = target
	}
	config.LabMappings = mappings
	config.PublicAuthorities = append([]string(nil), config.PublicAuthorities...)
	for _, authority := range config.PublicAuthorities {
		normal, _, port, err := parseAuthority(authority, true)
		if err != nil || normal != authority || port != "443" {
			return nil, errors.New("public allowlist requires canonical hostname:443")
		}
	}
	if len(config.PublicAuthorities) == 0 && len(config.LabMappings) == 0 {
		return nil, errors.New("empty allowlist")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{config: config, resolver: resolver, dial: dial, log: logger, ctx: ctx, cancel: cancel, slots: make(chan struct{}, config.MaxConnections), active: make(map[net.Conn]struct{})}, nil
}
func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == port
}
func parseAuthority(authority string, wildcard bool) (string, string, string, error) {
	if len(authority) > 260 || strings.ContainsAny(authority, "/@?#%\\\r\n\t ") {
		return "", "", "", errors.New("bad authority")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil || !validPort(port) {
		return "", "", "", errors.New("host and explicit port required")
	}
	host = strings.ToLower(host)
	if wildcard && strings.HasPrefix(host, "*.") {
		host = host[2:]
	} else if strings.Contains(host, "*") {
		return "", "", "", errors.New("bad wildcard")
	}
	if len(host) < 1 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return "", "", "", errors.New("bad host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", "", errors.New("bad DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", "", "", errors.New("ASCII host required")
			}
		}
	}
	return strings.ToLower(authority), host, port, nil
}
func matches(pattern, authority string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == authority
	}
	suffix := strings.TrimPrefix(pattern, "*")
	return strings.HasSuffix(authority, suffix) && len(authority) > len(suffix)
}

var special = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4")}

func PublicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range special {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
func (p *Proxy) target(ctx context.Context, authority string) (net.Conn, string, string, error) {
	normal, host, port, err := parseAuthority(authority, false)
	if err != nil {
		return nil, "", "", err
	}
	if target, ok := p.config.LabMappings[normal]; ok {
		c, e := p.dial(ctx, "tcp4", target)
		return c, target, "lab", e
	}
	allowed := false
	for _, pattern := range p.config.PublicAuthorities {
		if matches(pattern, normal) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, "", "", errors.New("authority denied")
	}
	addresses, err := p.resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, "", "", err
	}
	for i, ip := range addresses {
		if i >= 8 {
			break
		}
		if !PublicIPv4(ip) {
			continue
		}
		target := net.JoinHostPort(ip.String(), port)
		c, e := p.dial(ctx, "tcp4", target)
		if e == nil {
			return c, target, "public", nil
		}
		err = e
	}
	if err == nil {
		err = errors.New("no permitted public IPv4 address")
	}
	return nil, "", "public", err
}
func (p *Proxy) add(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.active[c] = struct{}{}
	return true
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	event := Event{ID: p.next.Add(1), GroupID: p.config.GroupID, StartedUnixMicros: time.Now().UnixMicro()}
	registered := false
	defer func() {
		event.FinishedUnixMicros = time.Now().UnixMicro()
		if p.log != nil {
			p.log(event)
		}
		if registered {
			<-p.slots
			p.wg.Done()
		}
	}()
	if r.Method != http.MethodConnect {
		event.ErrorKind = "method_denied"
		http.Error(w, "CONNECT only", 405)
		return
	}
	authority := r.URL.Host
	if authority == "" {
		authority = r.RequestURI
	}
	normal, _, _, err := parseAuthority(authority, false)
	if err != nil {
		event.ErrorKind = "invalid_authority"
		http.Error(w, "invalid authority", 400)
		return
	}
	event.Authority = normal
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		http.Error(w, "proxy closed", 503)
		return
	}
	select {
	case p.slots <- struct{}{}:
		p.wg.Add(1)
		registered = true
	default:
		p.mu.Unlock()
		http.Error(w, "capacity", 503)
		return
	}
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.config.DialTimeoutMS)*time.Millisecond)
	stop := context.AfterFunc(r.Context(), cancel)
	upstream, target, route, err := p.target(ctx, normal)
	stop()
	cancel()
	event.Route = route
	event.DialAddress = target
	if err != nil {
		event.ErrorKind = "dial_or_policy_denied"
		http.Error(w, "target unavailable or denied", 502)
		return
	}
	defer upstream.Close()
	event.UpstreamLocal = upstream.LocalAddr().String()
	event.UpstreamRemote = upstream.RemoteAddr().String()
	if !p.add(upstream) {
		http.Error(w, "proxy closed", 503)
		return
	}
	defer func() { p.mu.Lock(); delete(p.active, upstream); p.mu.Unlock() }()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		event.ErrorKind = "hijack_unavailable"
		http.Error(w, "CONNECT requires HTTP/1.1", 500)
		return
	}
	client, buffer, err := hijacker.Hijack()
	if err != nil {
		event.ErrorKind = "hijack_failed"
		return
	}
	defer client.Close()
	event.ClientRemote = client.RemoteAddr().String()
	if !p.add(client) {
		return
	}
	defer func() { p.mu.Lock(); delete(p.active, client); p.mu.Unlock() }()
	deadline := time.Now().Add(time.Duration(p.config.MaxTunnelMS) * time.Millisecond)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		event.ErrorKind = "response_failed"
		return
	}
	if err = buffer.Flush(); err != nil {
		event.ErrorKind = "response_failed"
		return
	}
	event.Accepted = true
	type result struct {
		n   int64
		err error
	}
	upDone := make(chan result, 1)
	go func() { n, e := io.Copy(upstream, buffer.Reader); closeWrite(upstream); upDone <- result{n, e} }()
	down, e := io.Copy(client, upstream)
	closeWrite(client)
	up := <-upDone
	event.UpBytes = up.n
	event.DownBytes = down
	if e != nil || up.err != nil {
		event.ErrorKind = "tunnel_closed_or_deadline"
	}
}
func closeWrite(c net.Conn) {
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	} else {
		_ = c.Close()
	}
}
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	connections := make([]net.Conn, 0, len(p.active))
	for c := range p.active {
		connections = append(connections, c)
	}
	p.mu.Unlock()
	for _, c := range connections {
		_ = c.Close()
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c Config) String() string {
	return fmt.Sprintf("CONNECT proxy with %d public patterns and %d fixed lab mappings", len(c.PublicAuthorities), len(c.LabMappings))
}

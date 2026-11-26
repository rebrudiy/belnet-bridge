// Package admin adds an irreversible, loopback-only quiesce operation to the
// frozen CONNECT proxy. Quiesce closes tunnels; it never stops an HTTP listener
// or the process that owns a capture network namespace.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rebrudiy/belnet-bridge/g03controls/connectproxy"
)

const ShutdownTimeout = 3 * time.Second

type Result struct {
	StartedUnixMicros          int64  `json:"started_unix_micros"`
	FinishedUnixMicros         int64  `json:"finished_unix_micros"`
	AcceptedTunnelsClosed      uint64 `json:"accepted_tunnels_closed"`
	AcceptedTunnelsClosedTotal uint64 `json:"accepted_tunnels_closed_total"`
	Result                     string `json:"result"`
}
type Controller struct {
	proxy          *connectproxy.Proxy
	once           sync.Once
	mu             sync.Mutex
	requested      bool
	completed      bool
	result         Result
	closedAccepted atomic.Uint64
}

// New's event callback must be passed to the proxy's existing event logger.
// Call Bind exactly once before serving requests. This construction avoids
// replacing or editing the immutable proxy implementation.
func New() *Controller { return &Controller{} }
func (c *Controller) Bind(p *connectproxy.Proxy) {
	if p == nil || c.proxy != nil {
		panic("proxy must be bound exactly once")
	}
	c.proxy = p
}
func (c *Controller) NoteEvent(e connectproxy.Event) {
	if e.Accepted {
		c.closedAccepted.Add(1)
	}
}

// ValidateControlAddress requires a literal loopback and an explicit nonzero
// port. Hostname resolution and wildcard/nonloopback binds are forbidden.
func ValidateControlAddress(address string) error {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return errors.New("control requires literal loopback:port")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || !ip.IsLoopback() {
		return errors.New("control bind must be a literal loopback address")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return errors.New("invalid control port")
	}
	return nil
}
func remoteLoopback(address string) bool {
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		return false
	}
	ip, e := netip.ParseAddr(host)
	return e == nil && ip.IsLoopback()
}

// Quiesce is idempotent and survives an admin HTTP client disconnect. It starts
// one bounded shutdown using a process-owned context, never request ownership.
// Counts cover accepted tunnel completions DURING this operation, not all
// historical tunnels and not independent native-session disconnects.
func (c *Controller) Quiesce() Result {
	c.once.Do(func() {
		if c.proxy == nil {
			panic("unbound proxy controller")
		}
		c.mu.Lock()
		c.requested = true
		c.mu.Unlock()
		before := c.closedAccepted.Load()
		r := Result{StartedUnixMicros: time.Now().UnixMicro()}
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		e := c.proxy.Shutdown(ctx)
		cancel()
		r.FinishedUnixMicros = time.Now().UnixMicro()
		r.AcceptedTunnelsClosedTotal = c.closedAccepted.Load()
		r.AcceptedTunnelsClosed = r.AcceptedTunnelsClosedTotal - before
		r.Result = "ok"
		if e != nil {
			r.Result = "shutdown_timeout"
		}
		c.mu.Lock()
		c.result = r
		c.completed = e == nil
		c.mu.Unlock()
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result
}
func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !remoteLoopback(r.RemoteAddr) {
		http.Error(w, "loopback control only", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/state":
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		c.mu.Lock()
		requested, completed := c.requested, c.completed
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"quiesced": requested, "shutdown_completed": completed, "accepted_tunnels_closed_total": c.closedAccepted.Load(), "snapshot_unix_micros": time.Now().UnixMicro()})
	case "/quiesce":
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		result := c.Quiesce()
		if result.Result != "ok" {
			w.WriteHeader(http.StatusGatewayTimeout)
		}
		_ = json.NewEncoder(w).Encode(result)
	default:
		http.NotFound(w, r)
	}
}

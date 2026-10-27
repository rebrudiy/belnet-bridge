package main

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"net/netip"
	"sync"

	"github.com/coder/websocket"
)

// Server terminates bridge clients. It looks like an ordinary website: only a
// request to the secret path with the right token is upgraded to a tunnel.
type Server struct {
	dev   Device
	pool  *IPPool
	path  string
	token string
	cover http.Handler // served to everyone else

	mu      sync.RWMutex
	clients map[netip.Addr]*websocket.Conn
}

func NewServer(dev Device, pool *IPPool, path, token string, cover http.Handler) *Server {
	return &Server{dev: dev, pool: pool, path: path, token: token, cover: cover, clients: map[netip.Addr]*websocket.Conn{}}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	got := r.Header.Get("Authorization")
	if r.URL.Path != s.path || subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+s.token)) != 1 {
		s.cover.ServeHTTP(w, r)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	ws.SetReadLimit(mtu + 100)
	defer ws.CloseNow()

	ip, err := s.pool.Acquire()
	if err != nil {
		ws.Close(websocket.StatusTryAgainLater, "full")
		return
	}
	defer s.pool.Release(ip)

	ctx := r.Context()
	if err := ws.Write(ctx, websocket.MessageText, []byte(hello(ip, s.pool.prefix, s.pool.Gateway()))); err != nil {
		return
	}
	s.mu.Lock()
	s.clients[ip] = ws
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ip)
		s.mu.Unlock()
	}()
	log.Printf("client %s connected as %s", r.RemoteAddr, ip)

	// client -> internet: only accept packets that use the address we assigned.
	for {
		_, pkt, err := ws.Read(ctx)
		if err != nil {
			log.Printf("client %s disconnected: %v", ip, err)
			return
		}
		if src, ok := srcIPv4(pkt); !ok || src != ip {
			continue
		}
		if _, err := s.dev.Write(pkt); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}

// RouteFromDevice delivers packets coming back from the internet to the right client.
func (s *Server) RouteFromDevice(ctx context.Context) error {
	buf := make([]byte, mtu+100)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			return err
		}
		dst, ok := dstIPv4(buf[:n])
		if !ok {
			continue
		}
		s.mu.RLock()
		ws := s.clients[dst]
		s.mu.RUnlock()
		if ws == nil {
			continue
		}
		if err := ws.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
			log.Printf("write to %s: %v", dst, err)
		}
	}
}

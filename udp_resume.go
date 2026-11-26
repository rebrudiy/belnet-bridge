package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/shaping"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

const resumeLifetime = 6 * time.Minute

// One socket belongs to an authenticated random client session, rather than a
// WebSocket. IWP therefore keeps the same source address after TLS reconnects.
type resumedUDP struct {
	udp               *net.UDPConn
	incoming          chan []byte
	closed            chan struct{}
	closeOnce         sync.Once
	attach            sync.Mutex
	cancel            context.CancelFunc
	done              chan struct{}
	last              time.Time // guarded by UDPBridge.sessionsMu
	active            int       // guarded by UDPBridge.sessionsMu
	incomingDrops     atomic.Uint64
	trackIncomingTime bool
	incomingMu        sync.Mutex
	incomingTimes     []time.Time
}

func (p *resumedUDP) dequeueIncomingTime() time.Time {
	if !p.trackIncomingTime {
		return time.Time{}
	}
	p.incomingMu.Lock()
	defer p.incomingMu.Unlock()
	if len(p.incomingTimes) == 0 {
		return time.Time{}
	}
	at := p.incomingTimes[0]
	p.incomingTimes = p.incomingTimes[1:]
	return at
}

func (p *resumedUDP) close() { p.closeOnce.Do(func() { close(p.closed); p.udp.Close() }) }

// resumed acquires a lease before the HTTP upgrade, so idle cleanup cannot
// reclaim the socket while an authenticated attachment is still starting.
func (s *UDPBridge) resumed(session string) (*resumedUDP, error) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.closed {
		return nil, errors.New("UDP session store is closed")
	}
	now := time.Now()
	for key, p := range s.sessions {
		select {
		case <-p.closed:
			delete(s.sessions, key)
			continue
		default:
		}
		if p.active == 0 && now.Sub(p.last) > resumeLifetime {
			p.close()
			delete(s.sessions, key)
		}
	}
	if p := s.sessions[session]; p != nil {
		p.last = now
		p.active++
		return p, nil
	}
	if len(s.sessions) >= cap(s.slots) {
		return nil, errors.New("retained UDP session capacity reached")
	}
	udp, err := net.DialUDP("udp", nil, s.Target)
	if err != nil {
		return nil, err
	}
	p := &resumedUDP{udp: udp, incoming: make(chan []byte, 64), closed: make(chan struct{}), last: now, active: 1, trackIncomingTime: s.trackIncomingTime}
	s.sessions[session] = p
	go func() {
		defer p.close()
		buf := make([]byte, maxUDPDatagram)
		for {
			n, err := udp.Read(buf)
			if err != nil {
				return
			}
			arrived := time.Now()
			packet := append([]byte(nil), buf[:n]...)
			if p.trackIncomingTime {
				p.incomingMu.Lock()
			}
			select {
			case p.incoming <- packet:
				if p.trackIncomingTime {
					p.incomingTimes = append(p.incomingTimes, arrived)
				}
			case <-p.closed:
				if p.trackIncomingTime {
					p.incomingMu.Unlock()
				}
				return
			default:
				p.incomingDrops.Add(1)
			}
			if p.trackIncomingTime {
				p.incomingMu.Unlock()
			}
		}
	}()
	return p, nil
}

func (s *UDPBridge) releaseResumed(p *resumedUDP) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	// Lease release and last-use renewal are one operation from cleanup's view.
	p.last = time.Now()
	p.active--
}

func (s *UDPBridge) Close() error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.closed = true
	for key, p := range s.sessions {
		p.close()
		delete(s.sessions, key)
	}
	return nil
}

func (s *UDPBridge) serveVersion2(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(wireconfig.SessionHeader)
	if _, err := wireconfig.ParseSession(sid); err != nil {
		http.Error(w, "invalid transport request", 400)
		return
	}
	profile, err := wireconfig.ParseProfile(r.Header.Get(wireconfig.ProfileHeader))
	if err != nil {
		http.Error(w, "invalid transport request", 400)
		return
	}
	p, err := s.resumed(sid)
	if err != nil {
		http.Error(w, "temporarily unavailable", 503)
		return
	}
	defer s.releaseResumed(p)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(shaping.MaxFrame)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	done := make(chan struct{})
	p.attach.Lock()
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
	p.cancel = cancel
	p.done = done
	p.attach.Unlock()
	defer close(done)
	sender, err := shaping.NewSender(profile.Down, nil)
	if err != nil {
		return
	}
	sendDone := make(chan error, 1)
	go func() {
		err := sender.Run(ctx, p.incoming, func(ctx context.Context, data []byte) error {
			return writeUDPFrame(ctx, ws, websocket.MessageBinary, data)
		})
		cancel()
		sendDone <- err
	}()
	defer func() { cancel(); ws.CloseNow(); <-sendDone }()
	// A failed writer must also interrupt the reader. Socket lifetime is separate.
	go func() {
		select {
		case <-ctx.Done():
		case <-p.closed:
			cancel()
		}
	}()
	for {
		typ, frame, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			return
		}
		packets, err := shaping.Decode(frame)
		if err != nil {
			return
		}
		for _, packet := range packets {
			if err := p.udp.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			if _, err := p.udp.Write(packet); err != nil {
				return
			}
		}
		s.sessionsMu.Lock()
		p.last = time.Now()
		s.sessionsMu.Unlock()
	}
}

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rebrudiy/belnet-bridge/internal/streamframe"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

const streamStageTimeout = 10 * time.Second

// Separate idle/header and body deadlines prevent a partial payload from
// retaining an allocation for the full idle period. The codec checks its
// length before its first body read/allocation.
func readStreamDatagram(conn net.Conn, idle, body time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
		return nil, err
	}
	return streamframe.Read(&streamStageReader{conn: conn, headerRemaining: 4, bodyTimeout: body})
}

type streamStageReader struct {
	conn            net.Conn
	headerRemaining int
	bodyTimeout     time.Duration
	bodyStarted     bool
}

func (r *streamStageReader) Read(p []byte) (int, error) {
	if r.headerRemaining == 0 && !r.bodyStarted {
		if err := r.conn.SetReadDeadline(time.Now().Add(r.bodyTimeout)); err != nil {
			return 0, err
		}
		r.bodyStarted = true
	}
	n, err := r.conn.Read(p)
	r.headerRemaining = max(0, r.headerRemaining-n)
	return n, err
}

func literalLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("plaintext stream endpoint requires a literal loopback address")
	}
	return nil
}

func sessionHash(sid []byte) string { v := sha256.Sum256(sid); return hex.EncodeToString(v[:]) }

// streamBridge is a local adapter behind an authenticated outer transport.
// Token holders share a principal; SID is not a per-VLESS-user identity.
type streamBridge struct {
	bridge      *UDPBridge
	metrics     *streamMetrics
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	workers     sync.WaitGroup
}

func newStreamBridge(target *net.UDPAddr, token string, limit int, metrics *streamMetrics) *streamBridge {
	b := NewUDPBridge(target, token, "", limit)
	b.trackIncomingTime = metrics != nil
	return &streamBridge{bridge: b, metrics: metrics, connections: make(map[net.Conn]struct{})}
}

func (s *streamBridge) serve(parent context.Context, listener net.Listener) error {
	if err := literalLoopback(listener.Addr().String()); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	stopDone := make(chan struct{})
	go func() { defer close(stopDone); <-ctx.Done(); listener.Close() }()
	defer func() { cancel(); listener.Close(); s.close(); s.workers.Wait(); <-stopDone }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			conn.Close()
			return nil
		}
		s.mu.Lock()
		if len(s.connections) >= cap(s.bridge.slots) {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.connections[conn] = struct{}{}
		s.workers.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.workers.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
			s.handle(ctx, conn)
		}()
	}
}

func (s *streamBridge) close() {
	s.mu.Lock()
	for c := range s.connections {
		c.Close()
	}
	s.mu.Unlock()
	s.bridge.Close()
}

func (s *streamBridge) handle(parent context.Context, conn net.Conn) {
	if conn.SetReadDeadline(time.Now().Add(streamStageTimeout)) != nil {
		return
	}
	sid, token, err := streamframe.ReadHandshake(conn)
	if err != nil || subtle.ConstantTimeCompare([]byte(token), []byte(s.bridge.Token)) != 1 {
		return
	}
	owner := sha256.Sum256([]byte(s.bridge.Token))
	p, err := s.bridge.resumed(hex.EncodeToString(owner[:]) + "/" + hex.EncodeToString(sid[:]))
	if err != nil {
		return
	}
	defer s.bridge.releaseResumed(p)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	p.attach.Lock()
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
	p.cancel, p.done = cancel, done
	p.attach.Unlock()
	defer close(done)
	epoch := s.metrics.open(sessionHash(sid[:]), p.udp.LocalAddr().String(), conn.RemoteAddr().String())
	defer func() { s.metrics.receiverDropped(epoch, p.incomingDrops.Load()); s.metrics.closed(epoch) }()
	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		select {
		case <-ctx.Done():
		case <-p.closed:
			cancel()
		}
		conn.Close()
	}()
	defer func() { cancel(); conn.Close(); <-stopDone }()
	if conn.SetWriteDeadline(time.Now().Add(streamStageTimeout)) != nil {
		return
	}
	if streamframe.WriteAccepted(conn) != nil {
		return
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-p.incoming:
				received := p.dequeueIncomingTime()
				s.metrics.receiverDropped(epoch, p.incomingDrops.Load())
				started := time.Now()
				if conn.SetWriteDeadline(time.Now().Add(streamStageTimeout)) != nil {
					s.metrics.failedWrite(epoch, len(packet), received, started, 0)
					return
				}
				if streamframe.Write(conn, packet) != nil {
					s.metrics.failedWrite(epoch, len(packet), received, started, 0)
					return
				}
				s.metrics.packetQueued(epoch, -1, len(packet), p.udp.LocalAddr().String(), received, started, 0)
			}
		}
	}()
	defer func() { cancel(); conn.Close(); <-writerDone }()
	for {
		// An idle stream also has a deadline: a live native peer sends keepalive
		// datagrams. Timeout reconnects keep the same retained UDP association.
		packet, err := readStreamDatagram(conn, 30*time.Second, streamStageTimeout)
		if err != nil {
			return
		}
		if p.udp.SetWriteDeadline(time.Now().Add(streamStageTimeout)) != nil {
			return
		}
		if _, err := p.udp.Write(packet); err != nil {
			return
		}
		s.metrics.packet(epoch, 1, len(packet), p.udp.LocalAddr().String())
	}
}

func runUDPStreamProxy(ctx context.Context, listener *net.UDPConn, upstream, token string, metrics *streamMetrics) error {
	return runUDPStreamProxyWithMaxAge(ctx, listener, upstream, token, metrics, 0)
}

func runUDPStreamProxyWithMaxAge(ctx context.Context, listener *net.UDPConn, upstream, token string, metrics *streamMetrics, maxQueueAge time.Duration) error {
	if maxQueueAge < 0 || maxQueueAge > time.Minute {
		return errors.New("max queue age requires 0..1m")
	}
	if err := literalLoopback(listener.LocalAddr().String()); err != nil {
		return err
	}
	if err := literalLoopback(upstream); err != nil {
		return err
	}
	if token == "" || len(token) > streamframe.MaxTokenLength {
		return errors.New("invalid stream access token length")
	}
	var observe func(*udpPeer, udpPacket, bool)
	if metrics != nil {
		observe = func(p *udpPeer, packet udpPacket, accepted bool) {
			id, _ := wireconfig.ParseSession(p.sessionID)
			metrics.input(sessionHash(id), len(packet.data), packet.received, accepted)
		}
	}
	return runUDPProxyWorkers(ctx, listener, true, 16, true, observe, func(ctx context.Context, listener *net.UDPConn, p *udpPeer) {
		backoff := 100 * time.Millisecond
		for ctx.Err() == nil {
			started := time.Now()
			err := streamPeerConnection(ctx, listener, p, upstream, token, metrics, maxQueueAge)
			if ctx.Err() != nil {
				return
			}
			id, _ := wireconfig.ParseSession(p.sessionID)
			metrics.disconnected(sessionHash(id), fmt.Sprintf("%T", err), p.queueDrops.Load())
			if time.Since(started) >= 30*time.Second {
				backoff = 100 * time.Millisecond
			}
			if !waitUDPReconnect(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 5*time.Second)
		}
	})
}

func streamPeerConnection(parent context.Context, listener *net.UDPConn, p *udpPeer, upstream, token string, metrics *streamMetrics, maxQueueAge time.Duration) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: streamStageTimeout}).DialContext(ctx, "tcp", upstream)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopDone := make(chan struct{})
	go func() { defer close(stopDone); <-ctx.Done(); conn.Close() }()
	defer func() { cancel(); conn.Close(); <-stopDone }()
	data, err := wireconfig.ParseSession(p.sessionID)
	if err != nil {
		return err
	}
	var sid [32]byte
	copy(sid[:], data)
	if err := conn.SetDeadline(time.Now().Add(streamStageTimeout)); err != nil {
		return err
	}
	if err := streamframe.WriteHandshake(conn, sid, token); err != nil {
		return err
	}
	if err := streamframe.ReadAccepted(conn); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	epoch := metrics.open(sessionHash(sid[:]), listener.LocalAddr().String(), conn.LocalAddr().String())
	metrics.policy(epoch, maxQueueAge)
	defer metrics.closed(epoch)
	readerDone := make(chan struct{})
	var readerError error // published by closing readerDone
	go func() {
		defer func() { close(readerDone); cancel() }()
		for {
			packet, err := readStreamDatagram(conn, 30*time.Second, streamStageTimeout)
			if err == nil {
				_, err = listener.WriteToUDP(packet, p.addr)
			}
			if err != nil {
				readerError = err
				return
			}
			metrics.packet(epoch, -1, len(packet), listener.LocalAddr().String())
		}
	}()
	defer func() { cancel(); conn.Close(); <-readerDone }()
	for {
		select {
		case <-ctx.Done():
			select {
			case <-readerDone:
				return readerError
			default:
			}
			return ctx.Err()
		case packet := <-p.queue:
			received := p.dequeueTime()
			attemptStarted := time.Now()
			if err := conn.SetWriteDeadline(time.Now().Add(streamStageTimeout)); err != nil {
				metrics.failedWrite(epoch, len(packet), received, attemptStarted, p.queueDrops.Load())
				return err
			}
			writeStarted := time.Now()
			if maxQueueAge > 0 && (received.IsZero() || writeStarted.Sub(received) > maxQueueAge) {
				metrics.expired(epoch, len(packet), received, writeStarted, maxQueueAge, p.queueDrops.Load())
				continue
			}
			if err := streamframe.Write(conn, packet); err != nil {
				metrics.failedWrite(epoch, len(packet), received, writeStarted, p.queueDrops.Load())
				return err
			}
			metrics.packetQueued(epoch, 1, len(packet), listener.LocalAddr().String(), received, writeStarted, p.queueDrops.Load())
		}
	}
}

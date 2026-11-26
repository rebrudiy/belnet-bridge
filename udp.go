package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

const maxUDPDatagram = 65507

func writeUDPFrame(ctx context.Context, ws *websocket.Conn, typ websocket.MessageType, payload []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ws.Write(writeCtx, typ, payload)
}

// UDPBridge terminates a transport on the first BelNet node. Its UDP target is
// fixed by the operator, never supplied by a client. Each WebSocket gets its own
// UDP socket so IWP can distinguish peers. No IP routing or NAT is done here.
type UDPBridge struct {
	Target            *net.UDPAddr
	Token             string
	Path              string
	slots             chan struct{}
	sessionsMu        sync.Mutex
	sessions          map[string]*resumedUDP
	closed            bool // guarded by sessionsMu; Close is terminal
	trackIncomingTime bool // set before use; lab-only queue telemetry
	lab               *serverLab
}

func NewUDPBridge(target *net.UDPAddr, token, path string, limit int) *UDPBridge {
	return &UDPBridge{Target: target, Token: token, Path: path, slots: make(chan struct{}, limit), sessions: make(map[string]*resumedUDP)}
}

func (s *UDPBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	benign := s.lab != nil && (r.URL.Path == "/lab/ws" || r.URL.Path == "/lab/traffic")
	if (!benign && r.URL.Path != s.Path) || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) != 1 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := io.WriteString(w, coverPage); err != nil {
			log.Printf("write cover page: %v", err)
		}
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.lab != nil {
		s.lab.annotate(r.RemoteAddr, r.Header.Get(wireconfig.TraceHeader))
	}
	if benign {
		if r.URL.Path == "/lab/traffic" {
			s.lab.workload(w, r)
			return
		}
		s.lab.echo(w, r)
		return
	}
	if r.Header.Get(wireconfig.VersionHeader) == "3" {
		s.serveVersion3(w, r)
		return
	}
	if r.Header.Get(wireconfig.VersionHeader) == "2" {
		s.serveVersion2(w, r)
		return
	}
	udp, err := net.DialUDP("udp", nil, s.Target)
	if err != nil {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	defer udp.Close()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(maxUDPDatagram)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if err := writeUDPFrame(ctx, ws, websocket.MessageText, []byte("belnet-udp-v1")); err != nil {
		return
	}
	log.Print("udp session connected")
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxUDPDatagram)
		for {
			n, err := udp.Read(buf)
			if err == nil {
				err = writeUDPFrame(ctx, ws, websocket.MessageBinary, buf[:n])
			}
			if err != nil {
				cancel()
				return
			}
		}
	}()
	defer func() {
		cancel()
		udp.Close()
		ws.CloseNow()
		<-done
		log.Print("udp session disconnected")
	}()
	for {
		typ, packet, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			ws.Close(websocket.StatusUnsupportedData, "binary datagrams required")
			return
		}
		if err := udp.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		if _, err = udp.Write(packet); err != nil {
			return
		}
	}
}

type udpPacket struct {
	peer     *net.UDPAddr
	data     []byte
	received time.Time
}

type udpPeer struct {
	addr       *net.UDPAddr
	queue      chan []byte
	cancel     context.CancelFunc
	last       time.Time // owned by RunUDPProxy's main loop
	sessionID  string
	queueDrops atomic.Uint64
	queueMu    sync.Mutex
	queueTimes []time.Time
}

func (p *udpPeer) dequeueTime() time.Time {
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	if len(p.queueTimes) == 0 {
		return time.Time{}
	}
	at := p.queueTimes[0]
	p.queueTimes = p.queueTimes[1:]
	return at
}

// RunUDPProxy provides a local UDP endpoint for a BelNet first-hop connection.
// It sends no raw UDP to the remote node: a failed TLS connection fails closed.
// Queues and peer count are bounded; UDP packets can be dropped under overload.
func RunUDPProxy(parent context.Context, listener *net.UDPConn, endpoint, token string, client *http.Client) error {
	return runUDPProxyWithLab(parent, listener, endpoint, token, client, nil)
}

func runUDPProxyWithLab(parent context.Context, listener *net.UDPConn, endpoint, token string, client *http.Client, lab *clientLab) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil {
		return errors.New("UDP transport requires a wss:// URL without embedded credentials")
	}
	if client == nil {
		client = http.DefaultClient
	}
	secureClient := *client
	// An operator-configured first hop is a fixed endpoint. Never send its token
	// to an HTTP redirect, including same-host TLS downgrades.
	secureClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return runUDPProxyWorkers(parent, listener, lab != nil, 64, false, nil, func(ctx context.Context, listener *net.UDPConn, p *udpPeer) {
		if lab != nil {
			serveExperimentalPeer(ctx, listener, p, endpoint, token, &secureClient, lab)
		} else {
			serveUDPPeer(ctx, listener, p, endpoint, token, &secureClient)
		}
	})
}

// The packet pump is shared by the authenticated WSS and local stream adapters.
// The worker supplies transport/retry policy; this loop owns peers and queues.
func runUDPProxyWorkers(parent context.Context, listener *net.UDPConn, retained bool, queueSize int, trackTiming bool, observe func(*udpPeer, udpPacket, bool), serve func(context.Context, *net.UDPConn, *udpPeer)) error {
	ctx, cancel := context.WithCancel(parent)
	in := make(chan udpPacket, 64)
	readErr := make(chan error, 1)
	closed := make(chan *udpPeer, 64)
	peers := make(map[string]*udpPeer)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		listener.Close()
		for _, p := range peers {
			p.cancel()
		}
		workers.Wait()
	}()
	go func() {
		buf := make([]byte, maxUDPDatagram)
		for {
			n, peer, err := listener.ReadFromUDP(buf)
			if err != nil {
				readErr <- err
				return
			}
			packet := udpPacket{peer, append([]byte(nil), buf[:n]...), time.Now()}
			select {
			case in <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-readErr:
			return err
		case packet := <-in:
			key := packet.peer.String()
			p := peers[key]
			if p == nil {
				if len(peers) >= 64 {
					continue
				}
				peerCtx, stop := context.WithCancel(ctx)
				p = &udpPeer{addr: packet.peer, queue: make(chan []byte, queueSize), cancel: stop}
				if retained {
					var err error
					p.sessionID, err = randomID()
					if err != nil {
						stop()
						return err
					}
				}
				peers[key] = p
				workers.Add(1)
				go func(p *udpPeer) {
					defer workers.Done()
					serve(peerCtx, listener, p)
					select {
					case closed <- p:
					case <-ctx.Done():
					}
				}(p)
			}
			p.last = time.Now()
			if trackTiming {
				p.queueMu.Lock()
			}
			accepted := false
			select {
			case p.queue <- packet.data:
				accepted = true
				if trackTiming {
					p.queueTimes = append(p.queueTimes, packet.received)
				}
			default:
				p.queueDrops.Add(1)
			}
			if observe != nil {
				observe(p, packet, accepted)
			}
			if trackTiming {
				p.queueMu.Unlock()
			}
		case p := <-closed:
			if peers[p.addr.String()] == p {
				delete(peers, p.addr.String())
			}
		case now := <-ticker.C:
			idleLimit := 2 * time.Minute
			if retained {
				idleLimit = resumeLifetime + time.Minute
			}
			for key, p := range peers {
				if now.Sub(p.last) > idleLimit {
					p.cancel()
					delete(peers, key)
				}
			}
		}
	}
}

func serveUDPPeer(ctx context.Context, listener *net.UDPConn, peer *udpPeer, url, token string, client *http.Client) {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		ws, _, err := websocket.Dial(dialCtx, url, &websocket.DialOptions{
			HTTPClient: client, HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err == nil {
			ws.SetReadLimit(maxUDPDatagram)
			typ, msg, helloErr := ws.Read(dialCtx)
			if helloErr != nil || typ != websocket.MessageText || string(msg) != "belnet-udp-v1" {
				err = fmt.Errorf("invalid UDP transport greeting: %v", helloErr)
				ws.CloseNow()
			}
		}
		stop()
		if err == nil {
			connectedAt := time.Now()
			log.Print("udp tunnel connected")
			err = relayUDPPeer(ctx, listener, peer, ws)
			// A greeting alone must not reset retries during a flapping outage.
			if time.Since(connectedAt) >= 30*time.Second {
				backoff = 100 * time.Millisecond
			}
			log.Printf("udp tunnel disconnected: %v", err)
		} else if ctx.Err() == nil {
			log.Printf("udp tunnel dial failed: %v", err)
		}
		if !waitUDPReconnect(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

func waitUDPReconnect(ctx context.Context, backoff time.Duration) bool {
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func relayUDPPeer(parent context.Context, listener *net.UDPConn, peer *udpPeer, ws *websocket.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(done)
		for {
			typ, packet, err := ws.Read(ctx)
			if err == nil && typ != websocket.MessageBinary {
				err = errors.New("expected binary UDP datagram")
			}
			if err == nil {
				_, err = listener.WriteToUDP(packet, peer.addr)
			}
			if err != nil {
				errs <- err
				return
			}
		}
	}()
	defer func() { cancel(); ws.CloseNow(); <-done }()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errs:
			return err
		case packet := <-peer.queue:
			if err := writeUDPFrame(ctx, ws, websocket.MessageBinary, packet); err != nil {
				return err
			}
		case <-ticker.C:
			pingCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			err := ws.Ping(pingCtx)
			stop()
			if err != nil {
				return err
			}
		}
	}
}

func runUDPServer(args []string) error {
	fs := flag.NewFlagSet("udp-server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "HTTPS listen address")
	target := fs.String("target", "", "fixed local BelNet IWP UDP address, e.g. 172.30.0.10:1090")
	cert := fs.String("cert", "", "TLS certificate")
	key := fs.String("key", "", "TLS private key")
	token := fs.String("token", os.Getenv("BRIDGE_TOKEN"), "access token (or BRIDGE_TOKEN)")
	path := fs.String("path", "/ws", "transport HTTP path")
	labControl := fs.String("lab-control", "", "loopback-only experiment control address (lab use)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *token == "" || *cert == "" || *key == "" {
		return errors.New("udp-server requires -target, -cert, -key and -token/BRIDGE_TOKEN")
	}
	addr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bridge := NewUDPBridge(addr, *token, *path, 64)
	defer bridge.Close()
	if *labControl != "" {
		bridge.lab = newServerLab()
		if err := startLabControl(ctx, *labControl, bridge.lab.handler()); err != nil {
			return err
		}
	}
	srv := &http.Server{
		Addr: *listen, Handler: bridge,
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Printf("HTTPS transport shutdown: %v", err)
			if err := srv.Close(); err != nil {
				log.Printf("close HTTPS transport: %v", err)
			}
		}
	}()
	log.Printf("first-hop HTTPS transport listening on %s", *listen)
	if bridge.lab != nil {
		listener, listenErr := net.Listen("tcp", *listen)
		if listenErr != nil {
			return listenErr
		}
		err = srv.ServeTLS(bridge.lab.listener(listener), *cert, *key)
	} else {
		err = srv.ListenAndServeTLS(*cert, *key)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runUDPClient(args []string) error {
	fs := flag.NewFlagSet("udp-client", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:2090", "local UDP listen address")
	url := fs.String("url", "", "first-hop WSS URL")
	token := fs.String("token", os.Getenv("BRIDGE_TOKEN"), "access token (or BRIDGE_TOKEN)")
	ca := fs.String("ca", "", "optional PEM CA to add to the system trust store")
	labControl := fs.String("lab-control", "", "loopback-only experiment control address (lab use)")
	observeDir := fs.String("lab-observe-dir", "", "optional encrypted-record observations directory (lab use)")
	profileFile := fs.String("profile", "", "v2 shaping profile JSON file; enables retained UDP sessions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *token == "" {
		return errors.New("udp-client requires -url and -token/BRIDGE_TOKEN")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			return err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("CA file contains no PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}
	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	log.Printf("local first-hop UDP transport listening on %s", conn.LocalAddr())
	if *labControl != "" || *profileFile != "" {
		lab := newClientLab(*observeDir)
		if *profileFile != "" {
			file, err := os.Open(*profileFile)
			if err != nil {
				return err
			}
			// Read one extra byte so a valid prefix cannot conceal an oversized
			// profile or trailing JSON beyond the input limit.
			data, err := io.ReadAll(io.LimitReader(file, 8193))
			closeErr := file.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if len(data) > 8192 {
				return errors.New("profile file is too large")
			}
			profile, err := wireconfig.DecodeProfile(bytes.NewReader(data))
			if err != nil {
				return err
			}
			lab.epoch.Profile = profile
		}
		if *labControl != "" {
			if err := startLabControl(ctx, *labControl, lab.handler()); err != nil {
				return err
			}
		}
		return runUDPProxyWithLab(ctx, conn, *url, *token, &http.Client{Transport: transport}, lab)
	}
	return RunUDPProxy(ctx, conn, *url, *token, &http.Client{Transport: transport})
}

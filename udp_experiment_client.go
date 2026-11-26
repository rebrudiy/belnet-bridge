package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/cell"
	"github.com/rebrudiy/belnet-bridge/internal/shaping"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

type clientTrace struct {
	peer          string
	cancel        context.CancelFunc
	epochID       string
	observation   traffic.Observation
	recorder      *traffic.Recorder
	fullRecorder  *traffic.Recorder
	sender        *shaping.Sender
	cells         *cell.Encoder
	connected     bool
	downBytes     atomic.Uint64
	downDatagrams atomic.Uint64
}

type clientLab struct {
	mu     sync.Mutex
	epoch  experimentEpoch
	rotate map[string]*clientTrace
	traces []*clientTrace
	dir    string
}

func newClientLab(dir string) *clientLab {
	return &clientLab{epoch: experimentEpoch{ID: "bootstrap", GroupID: "bootstrap", Split: traffic.SplitTrain, Class: traffic.ClassBelNet, Profile: shaping.Profile{Name: "baseline"}}, rotate: make(map[string]*clientTrace), dir: dir}
}

func (l *clientLab) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/epoch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		var epoch experimentEpoch
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&epoch); err != nil {
			http.Error(w, "invalid epoch", 400)
			return
		}
		if epoch.ID == "" || len(epoch.ID) > 128 || len(epoch.GroupID) > 128 {
			http.Error(w, "invalid epoch identifier", 400)
			return
		}
		if epoch.GroupID == "" {
			epoch.GroupID = epoch.ID
		}
		if epoch.Class == "" {
			epoch.Class = traffic.ClassBelNet
		}
		if epoch.Split != "train" && epoch.Split != "validation" && epoch.Split != "test" {
			http.Error(w, "invalid split", 400)
			return
		}
		if epoch.Class != traffic.ClassBelNet && epoch.Class != traffic.ClassBenign {
			http.Error(w, "invalid class", 400)
			return
		}
		if err := epoch.Profile.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if epoch.Cells != nil {
			if err := epoch.Cells.Validate(); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		l.mu.Lock()
		l.epoch = epoch
		for _, trace := range l.rotate {
			trace.cancel()
		}
		l.mu.Unlock()
		writeJSON(w, map[string]any{"epoch": epoch.ID, "ok": true})
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, l.state()) })
	return mux
}

func (l *clientLab) state() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	observations := []traffic.Observation{}
	fullObservations := []traffic.Observation{}
	stats := []shaping.Stats{}
	cellStats := []cell.Stats{}
	connected, ready := false, true
	var wireUp, wireDown, udpUp, udpDown uint64
	connections := []map[string]any{}
	for _, trace := range l.traces {
		if trace.epochID != l.epoch.ID {
			continue
		}
		obs := trace.observation
		obs.Events = trace.recorder.EventsSnapshot()
		if len(obs.Events) > 0 {
			observations = append(observations, obs)
		}
		full := trace.observation
		full.Events = trace.fullRecorder.EventsSnapshot()
		if len(full.Events) > 0 {
			fullObservations = append(fullObservations, full)
		}
		if trace.connected {
			connected = true
			ready = ready && trace.recorder.Ready()
		}
		out, in := trace.recorder.WireBytes()
		wireUp += out
		wireDown += in
		udpDown += trace.downBytes.Load()
		connections = append(connections, map[string]any{"session_id": trace.observation.SessionID, "connected": trace.connected, "ready": trace.recorder.Ready(), "records": len(obs.Events)})
		if trace.sender != nil {
			snapshot := trace.sender.Snapshot()
			stats = append(stats, snapshot)
			udpUp += snapshot.InputBytes
		}
		if trace.cells != nil {
			snapshot := trace.cells.Snapshot()
			cellStats = append(cellStats, snapshot)
			udpUp += snapshot.InputBytes
		}
	}
	return map[string]any{"epoch": l.epoch.ID, "connected": connected, "ready": connected && ready && len(observations) > 0, "observations": observations, "full_observations": fullObservations, "shaping_stats": stats, "cell_stats": cellStats, "connections": connections, "wire_bytes": map[string]uint64{"up": wireUp, "down": wireDown}, "udp_bytes": map[string]uint64{"up": udpUp, "down": udpDown}}
}

func (l *clientLab) begin(peer string, cancel context.CancelFunc) (experimentEpoch, *clientTrace, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id, err := randomID()
	if err != nil {
		return experimentEpoch{}, nil, err
	}
	epoch := l.epoch
	trace := &clientTrace{peer: peer, cancel: cancel, epochID: epoch.ID, observation: traffic.Observation{SessionID: id, GroupID: epoch.GroupID, Split: epoch.Split, Class: epoch.Class, Profile: epoch.Profile.Name}, recorder: traffic.NewRecorder(), fullRecorder: traffic.NewCaptureRecorder()}
	if epoch.Cells != nil {
		trace.observation.Profile = epoch.Cells.Name
	}
	l.rotate[peer] = trace
	l.traces = append(l.traces, trace)
	if len(l.traces) > 1024 {
		l.traces = l.traces[len(l.traces)-1024:]
	}
	return epoch, trace, nil
}

func (l *clientLab) finish(trace *clientTrace) error {
	l.mu.Lock()
	trace.connected = false
	if l.rotate[trace.peer] == trace {
		delete(l.rotate, trace.peer)
	}
	obs := trace.observation
	obs.Events = trace.recorder.EventsSnapshot()
	l.mu.Unlock()
	if l.dir != "" {
		if err := os.MkdirAll(l.dir, 0700); err != nil {
			return fmt.Errorf("create observation directory: %w", err)
		}
		data, err := json.Marshal(obs)
		if err != nil {
			return fmt.Errorf("encode observation: %w", err)
		}
		if err := os.WriteFile(filepath.Join(l.dir, obs.SessionID+".json"), append(data, '\n'), 0600); err != nil {
			return fmt.Errorf("write observation: %w", err)
		}
	}
	return nil
}

func serveExperimentalPeer(parent context.Context, listener *net.UDPConn, peer *udpPeer, endpoint, token string, client *http.Client, lab *clientLab) {
	backoff := 100 * time.Millisecond
	for parent.Err() == nil {
		ctx, cancel := context.WithCancel(parent)
		epoch, trace, err := lab.begin(peer.sessionID, cancel)
		if err != nil {
			cancel()
			return
		}
		connectedAt := time.Now()
		err = experimentalConnection(ctx, listener, peer, endpoint, token, client, lab, epoch, trace)
		cancel()
		if err := lab.finish(trace); err != nil {
			log.Printf("save transport observation: %v", err)
		}
		if parent.Err() != nil {
			return
		}
		lab.mu.Lock()
		rotated := lab.epoch.ID != epoch.ID
		lab.mu.Unlock()
		if rotated {
			backoff = 100 * time.Millisecond
			continue
		}
		if time.Since(connectedAt) >= 30*time.Second {
			backoff = 100 * time.Millisecond
		}
		log.Printf("experimental UDP transport disconnected: %v", err)
		if !waitUDPReconnect(parent, backoff) {
			return
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

func experimentalConnection(ctx context.Context, listener *net.UDPConn, peer *udpPeer, endpoint, token string, client *http.Client, lab *clientLab, epoch experimentEpoch, trace *clientTrace) error {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return errors.New("experimental transport requires an explicit HTTP transport")
	}
	transport = transport.Clone()
	transport.DisableKeepAlives = true
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return traffic.ObserveConn(traffic.ObserveConn(conn, true, trace.fullRecorder), true, trace.recorder), nil
	}
	defer transport.CloseIdleConnections()
	secure := *client
	secure.Transport = transport
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	headers, err := wireconfig.Headers(token, peer.sessionID, epoch.Profile, parsed.RequestURI())
	if epoch.Cells != nil {
		headers, err = cellHeaders(token, peer.sessionID, *epoch.Cells, parsed.RequestURI())
	}
	if err != nil {
		return err
	}
	headers.Set(wireconfig.TraceHeader, trace.observation.SessionID)
	dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	ws, _, err := websocket.Dial(dialCtx, endpoint, &websocket.DialOptions{HTTPClient: &secure, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	stop()
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(shaping.MaxFrame)
	if epoch.Cells != nil {
		encoder := cell.NewEncoder(nil)
		lab.mu.Lock()
		trace.cells = encoder
		trace.connected = true
		lab.mu.Unlock()
		return relayCells(ctx, listener, peer, ws, encoder, *epoch.Cells, trace)
	}
	sender, err := shaping.NewSender(epoch.Profile.Up, nil)
	if err != nil {
		return err
	}
	lab.mu.Lock()
	trace.sender = sender
	trace.connected = true
	lab.mu.Unlock()
	return relayExperimental(ctx, listener, peer, ws, sender, trace)
}

func relayExperimental(parent context.Context, listener *net.UDPConn, peer *udpPeer, ws *websocket.Conn, sender *shaping.Sender, trace *clientTrace) error {
	ctx, cancel := context.WithCancel(parent)
	errorsOut := make(chan error, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			typ, frame, err := ws.Read(ctx)
			if err != nil {
				errorsOut <- err
				return
			}
			if typ != websocket.MessageBinary {
				errorsOut <- errors.New("expected framed datagrams")
				return
			}
			packets, err := shaping.Decode(frame)
			if err != nil {
				errorsOut <- err
				return
			}
			for _, packet := range packets {
				trace.downBytes.Add(uint64(len(packet)))
				trace.downDatagrams.Add(1)
				if _, err := listener.WriteToUDP(packet, peer.addr); err != nil {
					errorsOut <- err
					return
				}
			}
		}
	}()
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		errorsOut <- sender.Run(ctx, peer.queue, func(ctx context.Context, frame []byte) error {
			return writeUDPFrame(ctx, ws, websocket.MessageBinary, frame)
		})
	}()
	defer func() { cancel(); ws.CloseNow(); <-done; <-sendDone }()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errorsOut:
			return err
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

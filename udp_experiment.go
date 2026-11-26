package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/shaping"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
)

func randomID() (string, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

// The experiment API is deliberately limited to a loopback address. It is not
// a remotely accessible administration interface for production deployments.
func startLabControl(ctx context.Context, address string, handler http.Handler) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("lab control requires a literal loopback address")
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			log.Printf("close lab control: %v", err)
		}
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("serve lab control: %v", err)
		}
	}()
	return nil
}

type experimentEpoch struct {
	ID      string          `json:"id"`
	GroupID string          `json:"group_id"`
	Split   string          `json:"split"`
	Class   string          `json:"class"`
	Profile shaping.Profile `json:"profile"`
	Cells   *cellProfile    `json:"cells,omitempty"`
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write lab response: %v", err)
	}
}

type serverLab struct {
	mu         sync.Mutex
	model      *traffic.Model
	modelSHA   string
	enforce    bool
	decisions  []map[string]any
	traceIDs   map[string]string
	cooldown   time.Duration
	denied     map[string]time.Time
	generation uint64
}

func newServerLab() *serverLab {
	return &serverLab{traceIDs: make(map[string]string), denied: make(map[string]time.Time)}
}

// appendDecision is called with mu held, including pre-TLS cooldown rejects.
func (l *serverLab) appendDecision(decision map[string]any) {
	l.decisions = append(l.decisions, decision)
	if len(l.decisions) > 100000 {
		l.decisions = l.decisions[50000:]
	}
}

func (l *serverLab) annotate(remote, id string) {
	if len(id) != 64 {
		return
	}
	l.mu.Lock()
	l.traceIDs[remote] = id
	l.mu.Unlock()
}

func (l *serverLab) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/model", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		var request struct {
			Model           *traffic.Model `json:"model"`
			Enforce         bool           `json:"enforce"`
			CooldownSeconds int            `json:"cooldown_seconds"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024*1024)).Decode(&request); err != nil {
			http.Error(w, "invalid model", 400)
			return
		}
		if request.Enforce && request.Model == nil {
			http.Error(w, "enforcement requires a model", 400)
			return
		}
		if request.CooldownSeconds < 0 || request.CooldownSeconds > 120 {
			http.Error(w, "cooldown_seconds must be 0..120", 400)
			return
		}
		var hash string
		if request.Model != nil {
			data, err := json.Marshal(request.Model)
			if err != nil {
				http.Error(w, "invalid model", 400)
				return
			}
			validated, err := traffic.Load(bytes.NewReader(data))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			request.Model = validated
			sum := sha256.Sum256(data)
			hash = hex.EncodeToString(sum[:])
		}
		l.mu.Lock()
		l.model = request.Model
		l.modelSHA = hash
		l.enforce = request.Enforce
		l.cooldown = time.Duration(request.CooldownSeconds) * time.Second
		l.denied = make(map[string]time.Time)
		l.generation++
		l.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "model_sha256": hash, "enforce": request.Enforce})
	})
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		selected := append([]map[string]any(nil), l.decisions...)
		if id := r.URL.Query().Get("session_id"); id != "" {
			selected = []map[string]any{}
			for _, decision := range l.decisions {
				if decision["session_id"] == id {
					selected = append(selected, decision)
				}
			}
		}
		l.mu.Unlock()
		writeJSON(w, map[string]any{"decisions": selected})
	})
	return mux
}

func (l *serverLab) echo(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(65536)
	for {
		typ, data, err := ws.Read(r.Context())
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			return
		}
		if err := writeUDPFrame(r.Context(), ws, typ, data); err != nil {
			return
		}
	}
}

type monitoredListener struct {
	net.Listener
	lab *serverLab
}

func (l *serverLab) listener(ln net.Listener) net.Listener {
	return &monitoredListener{Listener: ln, lab: l}
}

type monitoredConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *monitoredConn) Close() error { c.once.Do(func() { close(c.done) }); return c.Conn.Close() }

func (l *monitoredListener) Accept() (net.Conn, error) {
	var raw net.Conn
	for {
		var err error
		raw, err = l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
		l.lab.mu.Lock()
		until := l.lab.denied[host]
		blocked := time.Now().Before(until)
		if blocked {
			l.lab.appendDecision(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "remote": raw.RemoteAddr().String(), "blocked": true, "enforced": true, "complete": false, "termination": "persistent_cooldown", "model_sha256": l.lab.modelSHA})
		}
		l.lab.mu.Unlock()
		if !blocked {
			break
		}
		raw.Close()
	}
	recorder := traffic.NewRecorder()
	conn := &monitoredConn{Conn: traffic.ObserveConn(raw, false, recorder), done: make(chan struct{})}
	l.lab.mu.Lock()
	model, hash, enforce := l.lab.model, l.lab.modelSHA, l.lab.enforce
	generation := l.lab.generation
	l.lab.mu.Unlock()
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(20 * time.Second)
		defer deadline.Stop()
		save := func(reason string) {
			complete := recorder.Ready() && !recorder.Malformed()
			obs := traffic.Observation{Events: recorder.EventsSnapshot()}
			blocked, score := false, 0.0
			if complete && model != nil {
				score = model.Score(obs)
				blocked = model.Block(obs)
			}
			willEnforce := complete && enforce && blocked && reason == "window_complete"
			out, in := recorder.WireBytes()
			decision := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "remote": raw.RemoteAddr().String(), "model_sha256": hash, "score": score, "blocked": blocked, "enforced": willEnforce, "complete": complete, "termination": reason, "records": len(obs.Events), "events": obs.Events, "wire_up": out, "wire_down": in}
			l.lab.mu.Lock()
			willEnforce = willEnforce && generation == l.lab.generation
			decision["enforced"] = willEnforce
			decision["generation"] = generation
			if willEnforce && l.lab.cooldown > 0 {
				host, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
				for key, until := range l.lab.denied {
					if time.Now().After(until) {
						delete(l.lab.denied, key)
					}
				}
				if len(l.lab.denied) < 4096 {
					l.lab.denied[host] = time.Now().Add(l.lab.cooldown)
				}
			}
			decision["session_id"] = l.lab.traceIDs[raw.RemoteAddr().String()]
			delete(l.lab.traceIDs, raw.RemoteAddr().String())
			l.lab.appendDecision(decision)
			if willEnforce {
				conn.Close()
			}
			l.lab.mu.Unlock()
		}
		for {
			select {
			case <-conn.done:
				save("connection_closed")
				return
			case <-deadline.C:
				save("observation_timeout")
				return
			case <-ticker.C:
				if !recorder.Ready() {
					continue
				}
				save("window_complete")
				return
			}
		}
	}()
	return conn, nil
}

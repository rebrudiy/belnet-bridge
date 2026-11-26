package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
)

func TestLabCooldownPersistsAndPolicyResetRejectsOldVerdicts(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprintf("reset-%v", reset), func(t *testing.T) {
			lab := newServerLab()
			lab.model = &traffic.Model{Threshold: .5, Trees: []traffic.Tree{{Nodes: []traffic.Node{{Leaf: true, Probability: 1}}}}}
			lab.enforce = true
			lab.cooldown = 30 * time.Second
			server := httptest.NewUnstartedServer(http.HandlerFunc(lab.echo))
			server.Listener = lab.listener(server.Listener)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			endpoint := "wss" + server.URL[len("https"):]
			ws, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
			if err := ws.Write(ctx, websocket.MessageBinary, []byte("start")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ws.Read(ctx); err != nil {
				t.Fatal(err)
			}
			if reset {
				request := httptest.NewRequest(http.MethodPost, "/model", bytes.NewBufferString(`{"model":null,"enforce":false}`))
				response := httptest.NewRecorder()
				lab.handler().ServeHTTP(response, request)
				if response.Code != 200 {
					t.Fatal(response.Body.String())
				}
			}
			time.Sleep(traffic.Window + 70*time.Millisecond)
			_ = ws.Write(ctx, websocket.MessageBinary, []byte("after"))
			_, _, err = ws.Read(ctx)
			if reset && err != nil {
				t.Fatalf("old model enforced after policy reset: %v", err)
			}
			if !reset && err == nil {
				t.Fatal("positive connection survived")
			}
			if !reset {
				other, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: server.Client()})
				if other != nil {
					other.CloseNow()
				}
				if err == nil {
					t.Fatal("reconnect bypassed persistent verdict")
				}
			}
			lab.mu.Lock()
			defer lab.mu.Unlock()
			if reset && len(lab.denied) != 0 {
				t.Fatal("old verdict contaminated new cooldown epoch")
			}
			if !reset {
				found := false
				for _, d := range lab.decisions {
					if d["termination"] == "persistent_cooldown" {
						found = true
					}
				}
				if !found {
					t.Fatal("reconnect denial not recorded")
				}
			}
		})
	}
}

func TestLabCensorActuallyClosesEncryptedConnection(t *testing.T) {
	lab := newServerLab()
	lab.model = &traffic.Model{Threshold: 0.5, Trees: []traffic.Tree{{Nodes: []traffic.Node{{Leaf: true, Probability: 1}}}}}
	lab.enforce = true
	server := httptest.NewUnstartedServer(http.HandlerFunc(lab.echo))
	server.Listener = lab.listener(server.Listener)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss"+server.URL[len("https"):], &websocket.DialOptions{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageBinary, []byte("before-window")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ws.Read(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(traffic.Window + 100*time.Millisecond)
	_ = ws.Write(ctx, websocket.MessageBinary, []byte("after-window"))
	if _, _, err := ws.Read(ctx); err == nil {
		t.Fatal("positive inline verdict left connection usable")
	}
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if len(lab.decisions) != 1 || lab.decisions[0]["enforced"] != true || lab.decisions[0]["complete"] != true {
		t.Fatal("missing actual enforcement decision")
	}
}

func TestClientTraceFinishRetainsOnlyCurrentRotation(t *testing.T) {
	lab := newClientLab("")
	_, first, err := lab.begin("peer", func() {})
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := lab.begin("peer", func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.finish(first); err != nil {
		t.Fatal(err)
	}
	if lab.rotate["peer"] != second {
		t.Fatal("finishing an old trace removed the current epoch rotation")
	}
	if err := lab.finish(second); err != nil {
		t.Fatal(err)
	}
	if len(lab.rotate) != 0 {
		t.Fatal("finished peer retained an epoch cancellation entry")
	}
}

func TestClientTraceFinishReportsObservationWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	lab := newClientLab(path)
	_, trace, err := lab.begin("peer", func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.finish(trace); err == nil {
		t.Fatal("observation persistence failure was lost")
	}
}

func TestLabObserverRetainsPartialClosedConnection(t *testing.T) {
	lab := newServerLab()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := lab.listener(listener).Accept(); accepted <- conn }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	client.Close()
	server.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		lab.mu.Lock()
		n := len(lab.decisions)
		var partial bool
		if n > 0 {
			partial = lab.decisions[0]["complete"] == false && lab.decisions[0]["termination"] == "connection_closed"
		}
		lab.mu.Unlock()
		if n > 0 {
			if !partial {
				t.Fatal("partial close was misclassified as complete")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("closed short connection disappeared from evidence")
}

func TestLabControlRejectsNonLoopback(t *testing.T) {
	if err := startLabControl(context.Background(), "0.0.0.0:0", http.NewServeMux()); err == nil {
		t.Fatal("public administration listener accepted")
	}
}

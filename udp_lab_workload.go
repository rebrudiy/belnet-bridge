package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// workload provides non-echo controls only when the loopback lab API is enabled.
// These are synthetic application workloads, never labelled real web sessions.
func (l *serverLab) workload(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(65536)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		return
	}
	var request struct {
		Family string `json:"family"`
		Seed   int64  `json:"seed"`
	}
	if json.Unmarshal(data, &request) != nil {
		return
	}
	rng := rand.New(rand.NewSource(request.Seed))
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()
	defer func() { cancel(); ws.CloseNow(); <-readDone }()
	for {
		var size, interval int
		switch request.Family {
		case "download":
			size, interval = 4096+rng.Intn(16000), 8+rng.Intn(60)
		case "upload":
			size, interval = 16+rng.Intn(120), 80+rng.Intn(140)
		case "push":
			size, interval = 200+rng.Intn(2800), 15+rng.Intn(150)
		case "chat":
			size, interval = 20+rng.Intn(700), 50+rng.Intn(300)
		case "rpc":
			size, interval = 80+rng.Intn(9000), 50+rng.Intn(220)
		case "stream":
			size, interval = 10000+rng.Intn(22000), 150+rng.Intn(300)
		default:
			return
		}
		payload := make([]byte, size)
		_, _ = rng.Read(payload)
		if err := writeUDPFrame(ctx, ws, websocket.MessageBinary, payload); err != nil || !waitUDPReconnect(ctx, time.Duration(interval)*time.Millisecond) {
			return
		}
	}
}

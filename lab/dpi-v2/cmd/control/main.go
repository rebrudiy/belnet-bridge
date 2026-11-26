// control generates declared synthetic non-echo workloads on the same HTTPS
// endpoint as BelNet. Actual Google/YouTube sessions are collected separately.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/shaping"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

func main() {
	endpoint := flag.String("url", "", "wss control endpoint")
	ca := flag.String("ca", "", "CA PEM")
	out := flag.String("out", "", "output directory")
	duration := flag.Duration("duration", 3200*time.Millisecond, "session duration")
	count := flag.Int("count", 12, "sessions per family, >=4")
	prefix := flag.String("prefix", "local", "whole-session ID prefix")
	seed := flag.Int64("seed", 2026111907, "declared workload seed")
	flag.Parse()
	if err := run(*endpoint, *ca, *out, *duration, *count, *prefix, *seed); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(endpoint, ca, out string, duration time.Duration, count int, prefix string, seed int64) error {
	if count < 4 || count > 32 || duration < time.Second || duration > 10*time.Second {
		return fmt.Errorf("invalid capture bounds")
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid CA")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := []string{}
	sem := make(chan struct{}, 4)
	for fi, family := range []string{"download", "upload", "push", "chat", "rpc", "stream"} {
		for i := 0; i < count; i++ {
			sem <- struct{}{}
			wg.Add(1)
			go func(fi int, family string, i int) {
				defer wg.Done()
				defer func() { <-sem }()
				split := "train"
				if i >= count/2 {
					split = "validation"
				}
				if i >= count*3/4 {
					split = "test"
				}
				id := fmt.Sprintf("%s-%s-%02d", prefix, family, i)
				if err := session(endpoint, pool, out, id, family, split, seed+int64(fi*100+i), duration); err != nil {
					mu.Lock()
					errors = append(errors, id+": "+err.Error())
					mu.Unlock()
				}
			}(fi, family, i)
		}
	}
	wg.Wait()
	data, _ := json.MarshalIndent(map[string]any{"errors": errors, "sessions": 6 * count, "observer": "client-Go-socket-callback", "real_public_traffic": false, "duration_ms": duration.Milliseconds()}, "", "  ")
	return os.WriteFile(filepath.Join(out, "acquisition.json"), append(data, '\n'), 0600)
}

func session(endpoint string, pool *x509.CertPool, out, id, family, split string, seed int64, duration time.Duration) error {
	recorder := traffic.NewRecorder()
	fullRecorder := traffic.NewCaptureRecorder()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return traffic.ObserveConn(traffic.ObserveConn(c, true, fullRecorder), true, recorder), nil
	}}
	defer transport.CloseIdleConnections()
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	headers, err := wireconfig.Headers(os.Getenv("BRIDGE_TOKEN"), fmt.Sprintf("%064x", seed), shaping.Profile{Name: "matched-control"}, u.RequestURI())
	if err != nil {
		return err
	}
	headers.Set(wireconfig.TraceHeader, fmt.Sprintf("%064x", seed+1000000))
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(65536)
	request, _ := json.Marshal(map[string]any{"family": family, "seed": seed})
	if err := ws.Write(ctx, websocket.MessageBinary, request); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	}()
	rng := rand.New(rand.NewSource(seed + 1))
	for ctx.Err() == nil {
		size, delay := 80+rng.Intn(600), 50+rng.Intn(200)
		if family == "download" || family == "stream" || family == "push" {
			size, delay = 20+rng.Intn(80), 200+rng.Intn(400)
		}
		if family == "upload" {
			size, delay = 2000+rng.Intn(14000), 8+rng.Intn(35)
		}
		payload := make([]byte, size)
		_, _ = rng.Read(payload)
		if ws.Write(ctx, websocket.MessageBinary, payload) != nil {
			break
		}
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	cancel()
	ws.CloseNow()
	<-done
	obs := traffic.Observation{SessionID: id, GroupID: id, Split: split, Class: traffic.ClassBenign, Profile: "local-matched-" + family, Events: recorder.EventsSnapshot()}
	full := obs
	full.Events = fullRecorder.EventsSnapshot()
	data, _ := json.MarshalIndent(map[string]any{"observation": obs, "full_observation": full, "eligible": recorder.Ready() && !recorder.Malformed(), "real_public_traffic": false, "family": family, "seed": seed}, "", "  ")
	return os.WriteFile(filepath.Join(out, id+".json"), append(data, '\n'), 0600)
}

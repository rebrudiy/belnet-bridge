// Command probe runs inside a private lab client's namespace.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/shaping"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

type proof struct {
	Nonce   string `json:"nonce"`
	Service string `json:"service"`
	Body    string `json:"body"`
}

type fetchResult struct {
	OK        bool   `json:"ok"`
	Nonce     string `json:"nonce"`
	BodyBytes int    `json:"body_bytes"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Error     string `json:"error,omitempty"`
}

type benignRequest struct {
	ID         string          `json:"id"`
	GroupID    string          `json:"group_id"`
	Split      string          `json:"split"`
	Seed       int64           `json:"seed"`
	DurationMS int             `json:"duration_ms"`
	Profile    shaping.Profile `json:"profile"`
}

type echoStats struct {
	SentFrames     uint64 `json:"sent_frames"`
	ReceivedFrames uint64 `json:"received_frames"`
	SentBytes      uint64 `json:"sent_bytes"`
	ReceivedBytes  uint64 `json:"received_bytes"`
}

type benignResult struct {
	Echo             echoStats             `json:"echo"`
	Observations     []traffic.Observation `json:"observations"`
	Errors           []string              `json:"errors,omitempty"`
	ApplicationBytes int64                 `json:"application_bytes"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: evo-probe serve | fetch URL BYTES | admin METHOD URL | benign")
	}
	switch os.Args[1] {
	case "serve":
		return serve()
	case "fetch":
		if len(os.Args) != 4 {
			return errors.New("fetch needs URL BYTES")
		}
		n, err := strconv.Atoi(os.Args[3])
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(fetch(os.Args[2], n))
	case "admin":
		if len(os.Args) != 4 {
			return errors.New("admin needs METHOD URL")
		}
		body, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, os.Args[2], os.Args[3], bytes.NewReader(body))
		if err != nil {
			return err
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
		if err != nil {
			return err
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("admin HTTP %d: %s", response.StatusCode, data)
		}
		_, err = os.Stdout.Write(data)
		return err
	case "benign":
		var request benignRequest
		if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
			return err
		}
		result, err := benign(request)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	default:
		return errors.New("unknown command")
	}
}

func randomID() string {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}

func serve() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/proof", func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if len(nonce) != 64 || err != nil || n < 0 || n > 128*1024 {
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof{nonce, "bb-evolution-service", strings.Repeat("x", n)})
		log.Printf("proof nonce=%s bytes=%d remote=%s", nonce, n, r.RemoteAddr)
	})
	srv := &http.Server{Addr: ":8081", Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second}
	return srv.ListenAndServe()
}

func fetch(endpoint string, n int) fetchResult {
	start := time.Now()
	nonce := randomID()
	result := fetchResult{Nonce: nonce}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", "127.3.2.1:53")
	}}
	transport := &http.Transport{DialContext: (&net.Dialer{Resolver: resolver}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	response, err := client.Get(strings.TrimRight(endpoint, "/") + "/proof?nonce=" + nonce + "&bytes=" + strconv.Itoa(n))
	if err != nil {
		result.Error = err.Error()
		result.ElapsedMS = time.Since(start).Milliseconds()
		return result
	}
	defer response.Body.Close()
	var data proof
	err = json.NewDecoder(io.LimitReader(response.Body, 256*1024)).Decode(&data)
	result.OK = err == nil && response.StatusCode == 200 && data.Nonce == nonce && data.Service == "bb-evolution-service" && len(data.Body) == n
	result.BodyBytes = len(data.Body)
	result.ElapsedMS = time.Since(start).Milliseconds()
	if !result.OK {
		result.Error = fmt.Sprintf("invalid service proof (HTTP %d): %v", response.StatusCode, err)
	}
	return result
}

func benign(request benignRequest) (benignResult, error) {
	if request.DurationMS < 2100 || request.DurationMS > 10000 {
		return benignResult{}, errors.New("duration must be 2100..10000ms")
	}
	if request.ID == "" || request.GroupID == "" {
		return benignResult{}, errors.New("benign needs unique IDs")
	}
	if err := request.Profile.Validate(); err != nil {
		return benignResult{}, err
	}
	pem, err := os.ReadFile("/lab/run/certs/ca.crt")
	if err != nil {
		return benignResult{}, err
	}
	token, err := os.ReadFile("/lab/run/certs/token")
	if err != nil {
		return benignResult{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return benignResult{}, errors.New("invalid lab CA")
	}
	var result benignResult
	var lock sync.Mutex
	var workers sync.WaitGroup
	for entry := 1; entry <= 2; entry++ {
		workers.Add(1)
		go func(entry int) {
			defer workers.Done()
			observation, echo, err := benignFlow(request, entry, roots, strings.TrimSpace(string(token)))
			lock.Lock()
			defer lock.Unlock()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("entry%d: %v", entry, err))
			}
			result.Observations = append(result.Observations, observation)
			result.ApplicationBytes += int64(echo.ReceivedBytes)
			result.Echo.SentFrames += echo.SentFrames
			result.Echo.ReceivedFrames += echo.ReceivedFrames
			result.Echo.SentBytes += echo.SentBytes
			result.Echo.ReceivedBytes += echo.ReceivedBytes
		}(entry)
	}
	workers.Wait()
	return result, nil
}

func benignFlow(request benignRequest, entry int, roots *x509.CertPool, token string) (traffic.Observation, echoStats, error) {
	recorder := traffic.NewRecorder()
	observation := traffic.Observation{SessionID: randomID(), GroupID: request.GroupID, Split: request.Split, Class: traffic.ClassBenign, Profile: request.Profile.Name}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return traffic.ObserveConn(conn, true, recorder), nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	headers, err := wireconfig.Headers(token, randomID(), request.Profile, "/lab/ws")
	if err != nil {
		return observation, echoStats{}, err
	}
	headers.Set(wireconfig.TraceHeader, observation.SessionID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.DurationMS+3000)*time.Millisecond)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://10.88.0.%d/lab/ws", 10+entry), &websocket.DialOptions{HTTPClient: client, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		observation.Events = recorder.EventsSnapshot()
		return observation, echoStats{}, err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(128 * 1024)
	readerCtx, readerCancel := context.WithCancel(ctx)
	pending := make(chan []byte, 128)
	readErrors := make(chan error, 1)
	done := make(chan struct{})
	var sentFrames, receivedFrames, sentBytes, receivedBytes atomic.Uint64
	sendError := func(err error) {
		select {
		case readErrors <- err:
		default:
		}
	}
	go func() {
		defer close(done)
		for expected := range pending {
			typ, payload, err := ws.Read(readerCtx)
			if err != nil {
				if readerCtx.Err() == nil {
					sendError(err)
				}
				return
			}
			if typ != websocket.MessageBinary || !bytes.Equal(payload, expected) {
				sendError(errors.New("WebSocket echo content mismatch"))
				return
			}
			receivedFrames.Add(1)
			receivedBytes.Add(uint64(len(payload)))
		}
	}()
	defer func() { readerCancel(); ws.CloseNow(); <-done }()
	workCtx, stop := context.WithTimeout(ctx, time.Duration(request.DurationMS)*time.Millisecond)
	defer stop()
	rng := mathrand.New(mathrand.NewSource(request.Seed + int64(entry)*107))
	family := int(request.Seed % 4)
	if family < 0 {
		family = -family
	}
	var transportError error
	running := true
	for running && workCtx.Err() == nil {
		select {
		case transportError = <-readErrors:
			running = false
		default:
		}
		if !running {
			break
		}
		var size, delay int
		switch family {
		case 0:
			size = 8 + rng.Intn(400)
			delay = 80 + rng.Intn(320)
		case 1:
			size = 500 + rng.Intn(900)
			delay = 20 + rng.Intn(80)
		case 2:
			size = 800 + rng.Intn(8192)
			delay = 1 + rng.Intn(20)
		default:
			size = 64 + rng.Intn(3000)
			delay = 10 + rng.Intn(150)
		}
		payload := make([]byte, size)
		_, _ = rng.Read(payload)
		select {
		case pending <- payload:
		case <-workCtx.Done():
			running = false
			continue
		}
		// Producer expiry stops new messages. It must not cancel an in-flight
		// WebSocket write: coder/websocket closes the connection on cancellation.
		writeCtx, writeCancel := context.WithTimeout(ctx, time.Second)
		writeErr := ws.Write(writeCtx, websocket.MessageBinary, payload)
		writeCancel()
		if writeErr != nil {
			transportError = writeErr
			break
		}
		sentFrames.Add(1)
		sentBytes.Add(uint64(len(payload)))
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		select {
		case <-workCtx.Done():
			timer.Stop()
		case transportError = <-readErrors:
			timer.Stop()
			running = false
		case <-timer.C:
		}
	}
	close(pending)
	select {
	case <-done:
	case <-ctx.Done():
		if transportError == nil {
			transportError = ctx.Err()
		}
		readerCancel()
		ws.CloseNow()
		<-done
	}
	select {
	case err := <-readErrors:
		if transportError == nil {
			transportError = err
		}
	default:
	}
	stats := echoStats{sentFrames.Load(), receivedFrames.Load(), sentBytes.Load(), receivedBytes.Load()}
	if transportError == nil && (stats.SentFrames != stats.ReceivedFrames || stats.SentBytes != stats.ReceivedBytes) {
		transportError = fmt.Errorf("echo incomplete: sent %d frames/%d bytes; received %d/%d", stats.SentFrames, stats.SentBytes, stats.ReceivedFrames, stats.ReceivedBytes)
	}
	observation.Events = recorder.EventsSnapshot()
	if recorder.Malformed() {
		return observation, stats, errors.New("malformed observed TLS stream")
	}
	return observation, stats, transportError
}

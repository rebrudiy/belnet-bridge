package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rebrudiy/belnet-bridge/g03controls/bench"
)

const burstSize = 16 * 1024 * 1024

var logMu sync.Mutex

func output(x any) { logMu.Lock(); defer logMu.Unlock(); _ = json.NewEncoder(os.Stdout).Encode(x) }
func main() {
	if len(os.Args) < 2 {
		panic("pki|serve|probe|admin|clock|signal")
	}
	var e error
	switch os.Args[1] {
	case "pki":
		e = pki(os.Args[2:])
	case "serve":
		e = serve(os.Args[2:])
	case "probe":
		e = probe(os.Args[2:])
	case "admin":
		e = admin(os.Args[2:])
	case "clock":
		output(map[string]any{"unix_micros": time.Now().UnixMicro(), "utc": time.Now().UTC().Format(time.RFC3339Nano), "clock": "linux-vm"})
	case "signal":
		e = signalPID(os.Args[2:])
	default:
		e = errors.New("unknown helper mode")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func pki(args []string) error {
	f := flag.NewFlagSet("pki", flag.ContinueOnError)
	dir := f.String("directory", "", "new private directory")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *dir == "" {
		return errors.New("directory required")
	}
	if e := os.Mkdir(*dir, 0700); e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "decoy.test"}, DNSNames: []string{"decoy.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return e
	}
	encoded, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(*dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(*dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0600); e != nil {
		return e
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	output(map[string]any{"spki": base64.StdEncoding.EncodeToString(sum[:]), "system_trust_modified": false})
	return nil
}
func burst(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if r.Method != "GET" || len(nonce) != 64 {
		http.Error(w, "bounded fixture GET/nonce required", 400)
		return
	}
	if _, e := hex.DecodeString(nonce); e != nil {
		http.Error(w, "nonce hex required", 400)
		return
	}
	start := time.Now()
	written := 0
	hash := sha256.New()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(burstSize))
	var err error
	for written < burstSize {
		n := min(64*1024, burstSize-written)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(((written+i)*31 + 17) % 251)
		}
		m, e := w.Write(b)
		hash.Write(b[:m])
		written += m
		if e != nil {
			err = e
			break
		}
		if m != n {
			err = io.ErrShortWrite
			break
		}
	}
	ev := map[string]any{"kind": "burst", "nonce": nonce, "started_unix_micros": start.UnixMicro(), "finished_unix_micros": time.Now().UnixMicro(), "bytes_written": written, "sha256": hex.EncodeToString(hash.Sum(nil))}
	if err != nil {
		ev["error"] = err.Error()
	}
	output(ev)
}
func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := f.String("private", "/work/private", "cert directory")
	ready := f.String("ready", "/work/server-ready.json", "file")
	if e := f.Parse(args); e != nil {
		return e
	}
	cert, e := tls.LoadX509KeyPair(filepath.Join(*dir, "cert.pem"), filepath.Join(*dir, "key.pem"))
	if e != nil {
		return e
	}
	handler := bench.NewHandler(func(e bench.Event) { output(map[string]any{"kind": "wss", "workload": e}) })
	mux := http.NewServeMux()
	mux.Handle("/ws", handler)
	mux.HandleFunc("/burst", burst)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 3 * time.Second}
	listener, e := net.Listen("tcp4", ":443")
	if e != nil {
		return e
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	raw, _ := json.Marshal(map[string]any{"ready": true, "at_unix_micros": time.Now().UnixMicro(), "listen": listener.Addr().String()})
	if e = os.WriteFile(*ready, raw, 0600); e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = handler.Shutdown(c)
		_ = server.Shutdown(c)
	}()
	e = server.Serve(tlsListener)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func admin(args []string) error {
	f := flag.NewFlagSet("admin", flag.ContinueOnError)
	method := f.String("method", "GET", "method")
	endpoint := f.String("url", "", "literal loopback admin URL")
	if e := f.Parse(args); e != nil {
		return e
	}
	u, e := url.Parse(*endpoint)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
		return errors.New("loopback HTTP only")
	}
	req, e := http.NewRequest(*method, *endpoint, nil)
	if e != nil {
		return e
	}
	client := &http.Client{Timeout: 2 * time.Second}
	r, e := client.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		return e
	}
	os.Stdout.Write(raw)
	if r.StatusCode != 200 {
		return fmt.Errorf("admin status%d", r.StatusCode)
	}
	return nil
}
func signalPID(args []string) error {
	f := flag.NewFlagSet("signal", flag.ContinueOnError)
	file := f.String("pid-file", "", "own PID file")
	name := f.String("expect", "tcpdump", "expected Linuxcomm")
	kind := f.String("signal", "", "USR1|INT|TERM|KILL")
	wait := f.Duration("wait", 0, "optional bounded exit wait")
	if e := f.Parse(args); e != nil {
		return e
	}
	raw, e := os.ReadFile(*file)
	if e != nil {
		return e
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if e != nil || pid < 2 {
		return errors.New("invalid own PID")
	}
	comm, e := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if os.IsNotExist(e) {
		output(map[string]any{"gone": true, "pid": pid})
		return nil
	}
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(comm)) != *name {
		return errors.New("PID comm differs; refusing signal")
	}
	signals := map[string]syscall.Signal{"USR1": syscall.SIGUSR1, "INT": syscall.SIGINT, "TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL}
	sig, ok := signals[*kind]
	if !ok {
		return errors.New("bad signal")
	}
	start := time.Now()
	e = syscall.Kill(pid, sig)
	if e != nil {
		return e
	}
	if *wait > 0 {
		deadline := time.Now().Add(min(*wait, 3*time.Second))
		gone := false
		for time.Now().Before(deadline) {
			comm, e = os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if os.IsNotExist(e) || strings.TrimSpace(string(comm)) != *name {
				gone = true
				break
			}
			stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if strings.Contains(string(stat), ") Z ") {
				gone = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !gone {
			return errors.New("PID exit wait deadline")
		}
	}
	output(map[string]any{"pid": pid, "signal": *kind, "started_unix_micros": start.UnixMicro(), "finished_unix_micros": time.Now().UnixMicro()})
	return nil
}
func probe(args []string) error {
	f := flag.NewFlagSet("probe", flag.ContinueOnError)
	proxy := f.String("proxy", "http://127.0.0.1:18080", "proxy")
	pin := f.String("spki", "", "SPKI")
	wsNonce := f.String("wss-nonce", "", "64hex")
	burstNonce := f.String("burst-nonce", "", "64hex")
	expected := f.String("expected-sha", "", "independent golden SHA")
	seed := f.Int64("seed", 20261119, "shared workload seed")
	if e := f.Parse(args); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	plan, e := bench.NewPlan("rpc", *seed, 5*time.Second, bench.DefaultBudget)
	if e != nil {
		return e
	}
	started := time.Now().UnixMicro()
	type wsResult struct {
		Result bench.ClientResult
		Error  string
	}
	done := make(chan wsResult, 1)
	go func() {
		r, e := bench.RunClient(ctx, "wss://decoy.test/ws", plan, bench.ClientOptions{Proxy: *proxy, SPKI: *pin, Nonce: *wsNonce})
		err := ""
		if e != nil {
			err = e.Error()
		}
		done <- wsResult{r, err}
	}()
	time.Sleep(500 * time.Millisecond)
	tlsConfig, e := bench.PinnedTLS("decoy.test", *pin)
	if e != nil {
		return e
	}
	p, e := url.Parse(*proxy)
	if e != nil {
		return e
	}
	transport := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	burstStart := time.Now().UnixMicro()
	r, e := client.Get("https://decoy.test/burst?nonce=" + *burstNonce)
	burstResult := map[string]any{"nonce": *burstNonce, "started_unix_micros": burstStart}
	if e != nil {
		burstResult["error"] = e.Error()
	} else {
		hash := sha256.New()
		n, readError := io.Copy(hash, r.Body)
		r.Body.Close()
		sum := hex.EncodeToString(hash.Sum(nil))
		burstResult["bytes"] = n
		burstResult["status"] = r.StatusCode
		burstResult["sha256"] = sum
		burstResult["sha256_matches_independent_golden"] = sum == *expected
		burstResult["exact"] = n == burstSize && sum == *expected && r.StatusCode == 200 && readError == nil
		if readError != nil {
			burstResult["error"] = readError.Error()
		}
	}
	burstResult["finished_unix_micros"] = time.Now().UnixMicro()
	var ws wsResult
	select {
	case ws = <-done:
	case <-ctx.Done():
		ws.Error = ctx.Err().Error()
	}
	passed := burstResult["exact"] == true && ws.Error == "" && ws.Result.CompletedDuration && ws.Result.SentMessages > 0 && ws.Result.RPCVerified == ws.Result.ReceivedMessages && ws.Result.RPCVerified > 0 && ws.Result.InvalidMessages == 0 && len(ws.Result.Errors) == 0
	output(map[string]any{"started_unix_micros": started, "finished_unix_micros": time.Now().UnixMicro(), "burst": burstResult, "wss": ws.Result, "wss_error": ws.Error, "functional_pass": passed})
	if !passed {
		return errors.New("functional fixture failed")
	}
	return nil
}

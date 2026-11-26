package bench

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type ClientOptions struct {
	Nonce string
	Proxy string
	SPKI  string
	DNS   string
}
type ClientResult struct {
	Nonce                   string   `json:"nonce"`
	CompletedDuration       bool     `json:"completed_duration"`
	Family                  string   `json:"family"`
	Seed                    int64    `json:"seed"`
	StartedUnixMicros       int64    `json:"started_unix_micros"`
	FinishedUnixMicros      int64    `json:"finished_unix_micros"`
	SentMessages            int      `json:"sent_messages"`
	ReceivedMessages        int      `json:"received_messages"`
	SentBytes               int64    `json:"sent_bytes"`
	ReceivedBytes           int64    `json:"received_bytes"`
	RPCVerified             int      `json:"rpc_verified"`
	DownloadPatternVerified int      `json:"download_pattern_verified_messages"`
	DownloadSHA256          string   `json:"download_received_sha256,omitempty"`
	UploadACKVerified       int      `json:"upload_ack_verified"`
	UploadAckedBytes        int64    `json:"upload_acked_bytes"`
	UploadVerifiedAllSent   bool     `json:"upload_verified_all_sent"`
	IntegrityStatus         string   `json:"integrity_status"`
	InvalidMessages         int      `json:"invalid_messages"`
	Errors                  []string `json:"errors"`
}

// PinnedTLS adds no OS roots. Empty pin uses normal public verification. A lab
// pin instead requires exactly its leaf key, valid hostname and validity times.
func PinnedTLS(host, pin string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if pin == "" {
		return c, nil
	}
	want, err := base64.StdEncoding.DecodeString(pin)
	if err != nil || len(want) != 32 {
		return nil, errors.New("SPKI pin must be base64 SHA256")
	}
	c.InsecureSkipVerify = true // replaced by exact-key/hostname/time verification below
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("missing lab certificate")
		}
		leaf := state.PeerCertificates[0]
		got := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(want, got[:]) != 1 {
			return errors.New("lab SPKI mismatch")
		}
		if err := leaf.VerifyHostname(host); err != nil {
			return errors.New("lab certificate hostname mismatch")
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return errors.New("lab certificate expired/not yet valid")
		}
		return nil
	}
	return c, nil
}
func RunClient(ctx context.Context, endpoint string, plan Plan, options ClientOptions) (ClientResult, error) {
	result := ClientResult{Family: plan.Family, Seed: plan.Seed, Errors: []string{}, IntegrityStatus: "not_applicable"}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return result, errors.New("ws/wss URL required")
	}
	nonce := options.Nonce
	if nonce == "" {
		nonce, err = NewNonce()
		if err != nil {
			return result, err
		}
	}
	result.Nonce = nonce
	wireURL, err := WorkloadURL(endpoint, plan, nonce)
	if err != nil {
		return result, err
	}
	u, err = url.Parse(wireURL)
	if err != nil {
		return result, err
	}
	if options.Proxy != "" && options.DNS != "" {
		return result, errors.New("CONNECT and native DNS modes must not be combined")
	}
	if u.Scheme == "ws" && options.SPKI != "" {
		return result, errors.New("SPKI pin cannot authenticate plaintext WS")
	}
	tlsConfig, err := PinnedTLS(u.Hostname(), options.SPKI)
	if err != nil {
		return result, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if options.DNS != "" {
		host, _, err := net.SplitHostPort(options.DNS)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			return result, errors.New("explicit DNS must be literal loopback:port")
		}
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", options.DNS)
		}}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: dialer.DialContext, DisableKeepAlives: true}
	if options.Proxy != "" {
		proxy, err := url.Parse(options.Proxy)
		if err != nil || proxy.Scheme != "http" || proxy.Hostname() == "" || proxy.User != nil {
			return result, errors.New("HTTP CONNECT proxy URL required")
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	defer transport.CloseIdleConnections()
	dialCtx, cancelDial := context.WithTimeout(ctx, 8*time.Second)
	ws, _, err := websocket.Dial(dialCtx, u.String(), &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}, HTTPHeader: nil, CompressionMode: websocket.CompressionDisabled})
	cancelDial()
	if err != nil {
		return result, err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(32768)
	work, cancel := context.WithTimeout(ctx, time.Duration(plan.DurationMS)*time.Millisecond)
	defer cancel()
	if err := ws.Write(work, websocket.MessageText, []byte(`{"start":true}`)); err != nil {
		return result, err
	}
	start := time.Now()
	result.StartedUnixMicros = start.UnixMicro()
	var mu sync.Mutex
	verifier := newIntegrityVerifier(plan)
	downloadHash := sha256.New()
	if plan.Family == "download" || plan.Family == "upload" {
		result.IntegrityStatus = "unverified_no_received_evidence"
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			typ, data, e := ws.Read(work)
			if e != nil {
				if work.Err() == nil {
					mu.Lock()
					result.Errors = append(result.Errors, "workload_read_closed_early")
					mu.Unlock()
					cancel()
				}
				return
			}
			mu.Lock()
			result.ReceivedBytes += int64(len(data))
			result.ReceivedMessages++
			if plan.Family == "download" {
				downloadHash.Write(data)
				if typ != websocket.MessageBinary || !verifier.download(data) {
					result.InvalidMessages++
				} else {
					result.DownloadPatternVerified++
					result.IntegrityStatus = "received_messages_verified"
				}
			}
			if plan.Family == "upload" {
				if n, ok := verifier.uploadACK(data); typ == websocket.MessageText && ok {
					result.UploadACKVerified++
					result.UploadAckedBytes = n
					result.IntegrityStatus = "acked_prefix_verified"
				} else {
					result.InvalidMessages++
				}
			}
			if typ == websocket.MessageText {
				var message struct {
					Kind   string `json:"kind"`
					Seq    int    `json:"seq"`
					Result int    `json:"result"`
				}
				if json.Unmarshal(data, &message) != nil {
					result.InvalidMessages++
				} else if plan.Family == "rpc" {
					if message.Kind != "rpc-response" || message.Seq < 0 || message.Seq >= len(plan.RPC) || message.Result != message.Seq*message.Seq+17 {
						result.InvalidMessages++
					} else {
						result.RPCVerified++
					}
				}
			}
			mu.Unlock()
		}
	}()
	for _, a := range plan.Up {
		if !sleepUntil(work, start.Add(time.Duration(a.AtMS)*time.Millisecond)) {
			break
		}
		payload, e := Payload(a.Kind, a.Seq, a.Bytes, plan.Seed, nil)
		if e != nil {
			cancel()
			break
		}
		typ := websocket.MessageText
		if a.Kind == "binary" {
			typ = websocket.MessageBinary
		}
		if e = ws.Write(work, typ, payload); e != nil {
			mu.Lock()
			result.Errors = append(result.Errors, "workload_write_failed")
			mu.Unlock()
			cancel()
			break
		}
		mu.Lock()
		result.SentMessages++
		result.SentBytes += int64(len(payload))
		mu.Unlock()
	}
	if work.Err() == nil {
		<-work.Done()
	}
	ws.CloseNow()
	<-readDone
	if plan.Family == "download" {
		result.DownloadSHA256 = hex.EncodeToString(downloadHash.Sum(nil))
		if result.InvalidMessages > 0 {
			result.IntegrityStatus = "FAILED"
		}
	}
	if plan.Family == "upload" {
		result.UploadVerifiedAllSent = result.UploadACKVerified > 0 && result.UploadAckedBytes == result.SentBytes && result.InvalidMessages == 0
		if result.InvalidMessages > 0 {
			result.IntegrityStatus = "FAILED"
		}
	}
	result.FinishedUnixMicros = time.Now().UnixMicro()
	result.CompletedDuration = ctx.Err() == nil && work.Err() == context.DeadlineExceeded && time.Since(start) >= time.Duration(plan.DurationMS)*time.Millisecond
	return result, nil
}

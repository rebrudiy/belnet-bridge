package bench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/coder/websocket"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFiniteNonEchoPlans(t *testing.T) {
	for _, family := range Families {
		p, e := NewPlan(family, 2026111901, 45*time.Second, DefaultBudget)
		if e != nil {
			t.Fatal(e)
		}
		again, _ := NewPlan(family, 2026111901, 45*time.Second, DefaultBudget)
		if !reflect.DeepEqual(p, again) {
			t.Fatal("seed not deterministic")
		}
		if p.UpBytes > DefaultBudget || p.DownBytes > DefaultBudget {
			t.Fatal("byte quota exceeded")
		}
		if family == "idle" && (len(p.Up) != 0 || len(p.Down) != 0) {
			t.Fatal("idle emitted dummy application traffic")
		}
		for _, a := range append(append([]Action{}, p.Up...), p.Down...) {
			if a.AtMS < 0 || a.AtMS >= 45000 || a.Bytes < 1 || a.Bytes > 32768 {
				t.Fatal("invalid action")
			}
		}
	}
	a, _ := Payload("rpc-request", 0, 512, 1, nil)
	b, _ := Payload("rpc-response", 0, 512, 8, map[string]any{"result": 17})
	if bytes.Equal(a, b) || !json.Valid(a) || !json.Valid(b) || len(a) != 512 || len(b) != 512 {
		t.Fatal("RPC response degenerates into echo")
	}
}
func TestBoundsAndUploadDigest(t *testing.T) {
	for _, family := range []string{"echo", "unknown"} {
		if _, e := NewPlan(family, 1, 45*time.Second, DefaultBudget); e == nil {
			t.Fatal("unknown family accepted")
		}
	}
	if _, e := NewPlan("chat", 1, 81*time.Second, DefaultBudget); e == nil {
		t.Fatal("unbounded duration accepted")
	}
	handler := NewHandler(nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "https://bench.test/upload", strings.NewReader("content")))
	var ack struct {
		Bytes int    `json:"accepted_bytes"`
		SHA   string `json:"sha256"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &ack); e != nil || ack.Bytes != 7 || ack.SHA == "content" || w.Body.String() == "content" {
		t.Fatal("upload did not return independent digest")
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://bench.test/bench?family=chat&seed=1&duration_ms=45001", nil))
	if w.Code != 400 {
		t.Fatal("query duration bound bypassed")
	}
}
func TestPublicVerificationAndExactLabSPKI(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.StartTLS()
	defer server.Close()
	cert := server.Certificate()
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(sum[:])
	normal, e := PinnedTLS("example.test", "")
	if e != nil || normal.InsecureSkipVerify {
		t.Fatal("public TLS verification disabled")
	}
	pinned, e := PinnedTLS("example.com", pin)
	if e != nil {
		t.Fatal(e)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if e := pinned.VerifyConnection(state); e != nil {
		t.Fatal(e)
	}
	wrong, _ := PinnedTLS("example.com", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if e := wrong.VerifyConnection(state); e == nil {
		t.Fatal("wrong lab key accepted")
	}
	wrongName, _ := PinnedTLS("unrelated.test", pin)
	if e := wrongName.VerifyConnection(state); e == nil {
		t.Fatal("pinned key skipped hostname validation")
	}
}
func TestShortLocalRPCFixture(t *testing.T) {
	handler := NewHandler(nil)
	server := httptest.NewServer(handler)
	defer server.Close()
	plan, e := NewPlan("rpc", 20261119, time.Second, DefaultBudget)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, e := RunClient(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws", plan, ClientOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if result.SentMessages == 0 || result.RPCVerified == 0 || result.InvalidMessages != 0 {
		t.Fatalf("local RPC fixture failed: %+v", result)
	}
}

func TestFixedLengthWireParametersAndNoLabels(t *testing.T) {
	a, _ := NewPlan("rpc", 1, 45*time.Second, DefaultBudget)
	b, _ := NewPlan("rpc", 20261119999, 45*time.Second, DefaultBudget)
	u, e := WorkloadURL("wss://decoy.test/ws", a, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	v, e := WorkloadURL("wss://decoy.test/ws", b, strings.Repeat("b", 64))
	if e != nil || len(u) != len(v) {
		t.Fatal("seed/nonce length leaked source assignment")
	}
	r := httptest.NewRequest("GET", u, nil)
	parsed, e := ParseQuery(r, DefaultBudget)
	if e != nil || parsed.Seed != 1 {
		t.Fatalf("fixed query roundtrip: %v", e)
	}
	if _, e := WorkloadURL("wss://decoy.test/ws?class=belnet", a, strings.Repeat("a", 64)); e == nil {
		t.Fatal("label accepted on wire")
	}
	if _, e := WorkloadURL("wss://decoy.test/ws", a, "short"); e == nil {
		t.Fatal("variable nonce accepted")
	}
}
func TestRPCBudgetNeverLeavesRequestsWithoutResponseDefinition(t *testing.T) {
	p, e := NewPlan("rpc", 3, 45*time.Second, 32768)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Up) != len(p.RPC) || p.DownBytes > 32768 || p.UpBytes > 32768 {
		t.Fatal("RPC quota desynchronized")
	}
}

func TestShutdownCancelsLongWorkloadAndFlushesEvent(t *testing.T) {
	events := make(chan Event, 1)
	handler := NewHandler(func(e Event) { events <- e })
	server := httptest.NewServer(handler)
	defer server.Close()
	plan, _ := NewPlan("push", 52, 45*time.Second, DefaultBudget)
	nonce := strings.Repeat("c", 64)
	url, e := WorkloadURL("ws"+strings.TrimPrefix(server.URL, "http")+"/ws", plan, nonce)
	if e != nil {
		t.Fatal(e)
	}
	ws, _, e := websocket.Dial(context.Background(), url, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.CloseNow()
	if e = ws.Write(context.Background(), websocket.MessageText, []byte(`{"start":true}`)); e != nil {
		t.Fatal(e)
	}
	// One server message proves the long workload is active before cancellation.
	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	if _, _, e = ws.Read(readCtx); e != nil {
		t.Fatal(e)
	}
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = handler.Shutdown(deadline); e != nil {
		t.Fatal(e)
	}
	select {
	case got := <-events:
		if got.CompletedDuration || got.ErrorKind == "" {
			t.Fatalf("shutdown falsely completed: %+v", got)
		}
	default:
		t.Fatal("Shutdown returned before active workload event was flushed")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 503 {
		t.Fatal("closed handler still accepting")
	}
}

func TestAllFamilyLocalFixtures(t *testing.T) {
	for _, family := range Families {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			handler := NewHandler(nil)
			server := httptest.NewServer(handler)
			defer server.Close()
			plan, e := NewPlan(family, 41, time.Second, DefaultBudget)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			got, e := RunClient(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws", plan, ClientOptions{})
			if e != nil {
				t.Fatal(e)
			}
			if got.InvalidMessages != 0 {
				t.Fatalf("invalid responses: %+v", got)
			}
			if family == "idle" {
				if got.SentMessages != 0 || got.ReceivedMessages != 0 {
					t.Fatal("idle generated application traffic")
				}
				return
			}
			if len(plan.Up) > 0 && got.SentMessages == 0 {
				t.Fatalf("no upward workload: %+v", got)
			}
			if (len(plan.Down) > 0 || len(plan.RPC) > 0) && got.ReceivedMessages == 0 {
				t.Fatalf("no downward workload: %+v", got)
			}
			if family == "rpc" && got.RPCVerified == 0 {
				t.Fatal("no verified RPC")
			}
		})
	}
}

func TestDownloadPatternAndUploadACKIntegrity(t *testing.T) {
	p, _ := NewPlan("download", 17, time.Second, DefaultBudget)
	v := newIntegrityVerifier(p)
	a := p.Down[0]
	payload, _ := Payload(a.Kind, a.Seq, a.Bytes, p.Seed+7, nil)
	if !v.download(payload) {
		t.Fatal("exact expected download rejected")
	}
	v = newIntegrityVerifier(p)
	payload[0] ^= 1
	if v.download(payload) {
		t.Fatal("corrupted download accepted")
	}
	p, _ = NewPlan("upload", 17, time.Second, DefaultBudget)
	v = newIntegrityVerifier(p)
	n := int64(p.Up[0].Bytes)
	good, _ := json.Marshal(map[string]any{"kind": "upload-ack", "accepted_bytes": n, "sha256": v.uploadPrefixes[n]})
	if got, ok := v.uploadACK(good); !ok || got != n {
		t.Fatal("valid ACK rejected")
	}
	bad, _ := json.Marshal(map[string]any{"kind": "upload-ack", "accepted_bytes": n, "sha256": strings.Repeat("0", 64)})
	if _, ok := v.uploadACK(bad); ok {
		t.Fatal("corrupted ACK accepted")
	}
	partial, _ := json.Marshal(map[string]any{"kind": "upload-ack", "accepted_bytes": n - 1, "sha256": v.uploadPrefixes[n]})
	if _, ok := v.uploadACK(partial); ok {
		t.Fatal("nonexistent prefix accepted")
	}
}
func TestLongFlowPlanCanActuallyRequest80Seconds(t *testing.T) {
	p, e := NewPlan("idle", 51, 80*time.Second, DefaultBudget)
	if e != nil {
		t.Fatal(e)
	}
	u, e := WorkloadURL("wss://decoy.test/ws", p, strings.Repeat("d", 64))
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseQuery(httptest.NewRequest("GET", u, nil), DefaultBudget)
	if e != nil || got.DurationMS != 80000 {
		t.Fatal("80s longflow not supported", e)
	}
}

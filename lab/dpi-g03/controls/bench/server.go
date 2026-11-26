package bench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/coder/websocket"
	"html/template"
	"io"
	"net/http"
	"sync"
	"time"
)

type Event struct {
	Nonce               string `json:"nonce"`
	StartedUnixMicros   int64  `json:"started_unix_micros"`
	FinishedUnixMicros  int64  `json:"finished_unix_micros"`
	Family              string `json:"family"`
	Seed                int64  `json:"seed"`
	RequestedDurationMS int64  `json:"requested_duration_ms"`
	CompletedDuration   bool   `json:"completed_duration"`
	UpBytes             int64  `json:"up_bytes"`
	DownBytes           int64  `json:"down_bytes"`
	UpMessages          int    `json:"up_messages"`
	DownMessages        int    `json:"down_messages"`
	ErrorKind           string `json:"error_kind,omitempty"`
}
type Handler struct {
	Log      func(Event)
	slots    chan struct{}
	MaxBytes int
	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewHandler(logger func(Event)) *Handler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Handler{Log: logger, slots: make(chan struct{}, 16), MaxBytes: DefaultBudget, ctx: ctx, cancel: cancel}
}

// Shutdown cancels and joins HTTP and hijacked WebSocket workloads, including event logging.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func ParseQuery(r *http.Request, budget int) (Plan, error) {
	return parseWorkload(r.URL.Query(), budget)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "backend closed", 503)
		return
	}
	select {
	case h.slots <- struct{}{}:
		h.wg.Add(1)
	default:
		h.mu.Unlock()
		http.Error(w, "capacity", 503)
		return
	}
	h.mu.Unlock()
	defer func() { <-h.slots; h.wg.Done() }()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.Path == "/healthz" || r.URL.Path == "/favicon.ico" {
		w.WriteHeader(204)
		return
	}
	if r.URL.Path == "/upload" {
		h.upload(w, r)
		return
	}
	plan, err := ParseQuery(r, h.MaxBytes)
	if err != nil {
		http.Error(w, "invalid finite workload", 400)
		return
	}
	switch r.URL.Path {
	case "/plan":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plan)
	case "/bench":
		h.page(w, r, plan)
	case "/ws":
		h.ws(w, r, plan)
	case "/download":
		h.download(w, r, plan)
	default:
		http.NotFound(w, r)
	}
}
func (h *Handler) download(w http.ResponseWriter, r *http.Request, p Plan) {
	if r.Method != "GET" || p.Family != "download" {
		http.Error(w, "download requires GET/download family", 400)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	start := time.Now()
	for _, a := range p.Down {
		if !sleepUntil(r.Context(), start.Add(time.Duration(a.AtMS)*time.Millisecond)) {
			return
		}
		payload, _ := Payload(a.Kind, a.Seq, a.Bytes, p.Seed, nil)
		if _, err := w.Write(payload); err != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}
func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	stop := context.AfterFunc(r.Context(), func() { _ = r.Body.Close() })
	defer stop()
	hash := sha256.New()
	n, err := io.Copy(hash, http.MaxBytesReader(w, r.Body, int64(h.MaxBytes)))
	if err != nil {
		http.Error(w, "upload limit or read failure", 413)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted_bytes": n, "sha256": hex.EncodeToString(hash.Sum(nil))})
}
func (h *Handler) ws(w http.ResponseWriter, r *http.Request, p Plan) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(32768)
	introCtx, stopIntro := context.WithTimeout(r.Context(), 5*time.Second)
	typ, intro, err := ws.Read(introCtx)
	stopIntro()
	var startMsg struct {
		Start bool `json:"start"`
	}
	if err != nil || typ != websocket.MessageText || len(intro) > 128 || json.Unmarshal(intro, &startMsg) != nil || !startMsg.Start {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(p.DurationMS)*time.Millisecond)
	defer cancel()
	start := time.Now()
	event := Event{StartedUnixMicros: start.UnixMicro(), Family: p.Family, Seed: p.Seed, Nonce: r.URL.Query().Get("nonce"), RequestedDurationMS: p.DurationMS}
	var mu sync.Mutex
	received := sha256.New()
	rpc := make(chan int, 16)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer cancel()
		for {
			typ, data, e := ws.Read(ctx)
			if e != nil {
				return
			}
			mu.Lock()
			event.UpBytes += int64(len(data))
			event.UpMessages++
			over := event.UpBytes > int64(h.MaxBytes)
			_, _ = received.Write(data)
			mu.Unlock()
			if over {
				cancel()
				return
			}
			if p.Family == "rpc" {
				var request struct {
					Kind string `json:"kind"`
					Seq  int    `json:"seq"`
				}
				if typ != websocket.MessageText || json.Unmarshal(data, &request) != nil || request.Kind != "rpc-request" || request.Seq < 0 || request.Seq >= len(p.RPC) {
					cancel()
					return
				}
				select {
				case rpc <- request.Seq:
				case <-ctx.Done():
					return
				default:
					cancel()
					return
				}
			}
		}
	}()
	write := func(kind string, seq, size int) bool {
		fields := map[string]any{}
		if kind == "upload-ack" {
			mu.Lock()
			fields["accepted_bytes"] = event.UpBytes
			fields["sha256"] = hex.EncodeToString(received.Sum(nil))
			mu.Unlock()
		}
		if kind == "rpc-response" {
			fields["result"] = seq*seq + 17
		}
		payload, e := Payload(kind, seq, size, p.Seed+7, fields)
		if e != nil {
			return false
		}
		message := websocket.MessageText
		if kind == "binary" {
			message = websocket.MessageBinary
		}
		if e = ws.Write(ctx, message, payload); e != nil {
			cancel()
			return false
		}
		mu.Lock()
		event.DownBytes += int64(len(payload))
		event.DownMessages++
		over := event.DownBytes > int64(h.MaxBytes)
		mu.Unlock()
		return !over
	}
	if p.Family == "rpc" {
		seen := make(map[int]bool)
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case seq := <-rpc:
				if seen[seq] {
					event.ErrorKind = "duplicate_rpc"
					break loop
				}
				seen[seq] = true
				response := p.RPC[seq]
				if !sleepUntil(ctx, time.Now().Add(time.Duration(response.DelayMS)*time.Millisecond)) || !write("rpc-response", seq, response.Bytes) {
					break loop
				}
			}
		}
	} else {
		for _, a := range p.Down {
			if !sleepUntil(ctx, start.Add(time.Duration(a.AtMS)*time.Millisecond)) || !write(a.Kind, a.Seq, a.Bytes) {
				break
			}
		}
		if ctx.Err() == nil {
			<-ctx.Done()
		}
	}
	cancel()
	ws.CloseNow()
	<-readerDone
	event.FinishedUnixMicros = time.Now().UnixMicro()
	event.CompletedDuration = time.Since(start) >= time.Duration(p.DurationMS)*time.Millisecond && r.Context().Err() == nil
	if !event.CompletedDuration && event.ErrorKind == "" {
		event.ErrorKind = "workload_ended_early"
	}
	if h.Log != nil {
		h.Log(event)
	}
}
func sleepUntil(ctx context.Context, t time.Time) bool {
	timer := time.NewTimer(time.Until(t))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
func (h *Handler) page(w http.ResponseWriter, r *http.Request, p Plan) {
	raw, _ := json.Marshal(p)
	data := struct{ Plan template.JS }{template.JS(raw)}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = pageTemplate.Execute(w, data)
}

var pageTemplate = template.Must(template.New("bench").Parse(`<!doctype html><meta charset="utf-8"><title>Network workload bench</title><p>Finite synthetic application workload.</p><pre id="status"></pre><script>
const plan={{.Plan}}, state=window.__bench={family:plan.family,seed:plan.seed,duration_ms:plan.duration_ms,sent_messages:0,received_messages:0,sent_bytes:0,received_bytes:0,integrity_status:'unverified_browser_byte_counters_only',errors:[],rpc_verified:0,invalid_messages:0,finished:false,completed_duration:false};
const url=new URL('/ws'+location.search,location.href);url.protocol=location.protocol==='https:'?'wss:':'ws:';const ws=new WebSocket(url);ws.binaryType='arraybuffer';
function payload(a){if(a.kind==='binary'){const p=new Uint8Array(a.bytes);for(let i=0;i<p.length;i++)p[i]=(plan.seed%251+a.seq*131+i*17)%251;return p;}const m={kind:a.kind,seq:a.seq,padding:''};const n=JSON.stringify(m).length;m.padding='x'.repeat(a.bytes-n);return JSON.stringify(m);}
ws.onopen=()=>{state.started_ms=performance.now();state.started_utc=new Date().toISOString();ws.send(JSON.stringify({start:true}));for(const a of plan.up)setTimeout(()=>{if(ws.readyState!==WebSocket.OPEN)return;const p=payload(a);ws.send(p);state.sent_messages++;state.sent_bytes+=typeof p==='string'?new TextEncoder().encode(p).length:p.byteLength;},a.at_ms);setTimeout(()=>{state.finished=true;state.completed_duration=ws.readyState===WebSocket.OPEN;state.finished_utc=new Date().toISOString();ws.close(1000,'bounded workload');},plan.duration_ms);};
ws.onmessage=e=>{if(plan.family==='rpc'){try{const m=JSON.parse(e.data);if(m.kind==='rpc-response'&&Number.isInteger(m.seq)&&m.seq>=0&&m.seq<plan.rpc.length&&m.result===m.seq*m.seq+17)state.rpc_verified++;else state.invalid_messages++;}catch{state.invalid_messages++;}}state.received_messages++;state.received_bytes+=typeof e.data==='string'?new TextEncoder().encode(e.data).length:e.data.byteLength;};ws.onerror=()=>state.errors.push('websocket_error');ws.onclose=e=>{if(!state.finished)state.errors.push('workload_closed_early');state.close_code=e.code;state.closed_utc=new Date().toISOString();};setInterval(()=>document.querySelector('#status').textContent=JSON.stringify(state,null,2),500);
</script>`))

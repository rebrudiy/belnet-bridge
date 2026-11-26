package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/cell"
	"github.com/rebrudiy/belnet-bridge/internal/wireconfig"
)

// cellProfile is an opt-in research policy. It intentionally does not claim the
// v2 100-ms/8x budgets: idle polling consumes bandwidth, and large UDP packets
// need multiple polls. This mode changes neither TLS authentication nor routing.
type cellProfile struct {
	Name               string `json:"name"`
	MinSize            int    `json:"min_size"`
	MaxSize            int    `json:"max_size"`
	IntervalMS         int    `json:"interval_ms"`
	JitterMS           int    `json:"jitter_ms"`
	SizeMode           string `json:"size_mode,omitempty"`
	DelayMode          string `json:"delay_mode,omitempty"`
	BurstCells         int    `json:"burst_cells,omitempty"`
	ReplyMinSize       int    `json:"reply_min_size,omitempty"`
	ReplyMaxSize       int    `json:"reply_max_size,omitempty"`
	PauseEvery         int    `json:"pause_every,omitempty"`
	PauseMS            int    `json:"pause_ms,omitempty"`
	RateBytesPerSecond int    `json:"rate_bytes_per_second,omitempty"`
}

func (p cellProfile) Validate() error {
	if len(p.Name) < 1 || len(p.Name) > 64 || !cell.ValidSize(p.MinSize) || !cell.ValidSize(p.MaxSize) || p.MinSize > p.MaxSize || p.IntervalMS < 2 || p.IntervalMS > 1000 || p.JitterMS < 0 || p.JitterMS > 1000 {
		return errors.New("invalid cell profile")
	}
	if (p.SizeMode != "" && p.SizeMode != "uniform" && p.SizeMode != "mixture") || (p.DelayMode != "" && p.DelayMode != "uniform" && p.DelayMode != "exponential") || p.BurstCells < 0 || p.BurstCells > 8 || p.PauseEvery < 0 || p.PauseEvery > 1024 || p.PauseMS < 0 || p.PauseMS > 2000 || p.RateBytesPerSecond < 0 || p.RateBytesPerSecond > 1024*1024 {
		return errors.New("invalid cell scheduling mode")
	}
	if p.ReplyMinSize != 0 || p.ReplyMaxSize != 0 {
		if !cell.ValidSize(p.ReplyMinSize) || !cell.ValidSize(p.ReplyMaxSize) || p.ReplyMinSize > p.ReplyMaxSize {
			return errors.New("invalid reply sizes")
		}
	}
	return nil
}

func (p cellProfile) size() (int, error) {
	if p.SizeMode != "mixture" {
		return randomRange(p.MinSize, p.MaxSize)
	}
	n, err := randomRange(0, 99)
	if err != nil {
		return 0, err
	}
	lo, hi := p.MinSize, p.MaxSize
	if n < 65 {
		hi = min(hi, max(lo, 512))
	} else if n < 95 {
		lo = min(hi, max(lo, 1024))
		hi = min(hi, max(lo, 1800))
	} else {
		lo = min(hi, max(lo, 3072))
	}
	return randomRange(lo, hi)
}

func (p cellProfile) delay(bytes int) (time.Duration, error) {
	jitter, err := randomRange(0, p.JitterMS)
	if err != nil {
		return 0, err
	}
	if p.DelayMode == "exponential" && p.JitterMS > 0 {
		n, e := randomRange(1, 1000000)
		if e != nil {
			return 0, e
		}
		jitter = min(4*p.JitterMS, int(-math.Log(float64(n)/1000001)*float64(p.JitterMS)))
	}
	d := time.Duration(p.IntervalMS+jitter) * time.Millisecond
	if p.RateBytesPerSecond > 0 {
		d = max(d, time.Duration(float64(bytes)/float64(p.RateBytesPerSecond)*float64(time.Second)))
	}
	return d, nil
}

func randomRange(low, high int) (int, error) {
	if low == high {
		return low, nil
	}
	var buf [8]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return 0, err
	}
	// The tiny modulo bias affects scheduling randomness only, not any key.
	return low + int(binary.LittleEndian.Uint64(buf[:])%uint64(high-low+1)), nil
}

func cellHeaders(token, session string, profile cellProfile, path string) (http.Header, error) {
	if _, err := wireconfig.ParseSession(session); err != nil {
		return nil, err
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+token)
	h.Set(wireconfig.VersionHeader, "3")
	h.Set(wireconfig.SessionHeader, session)
	h.Set(wireconfig.ProfileHeader, base64.RawURLEncoding.EncodeToString(data))
	size := len(path)
	for key, values := range h {
		for _, value := range values {
			size += len(key) + len(value) + 4
		}
	}
	if size > 2000 {
		return nil, fmt.Errorf("transport metadata too large")
	}
	h.Set("X-Client-Padding", strings.Repeat("a", 2048-size))
	return h, nil
}

func parseCellProfile(value string) (cellProfile, error) {
	var p cellProfile
	if len(value) > 4096 {
		return p, errors.New("cell profile too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return p, errors.New("trailing profile data")
	}
	return p, p.Validate()
}

func (s *UDPBridge) serveVersion3(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(wireconfig.SessionHeader)
	if _, err := wireconfig.ParseSession(sid); err != nil {
		http.Error(w, "invalid transport request", 400)
		return
	}
	profile, err := parseCellProfile(r.Header.Get(wireconfig.ProfileHeader))
	if err != nil {
		http.Error(w, "invalid transport request", 400)
		return
	}
	p, err := s.resumed(sid)
	if err != nil {
		http.Error(w, "temporarily unavailable", 503)
		return
	}
	defer s.releaseResumed(p)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(int64(profile.MaxSize))
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	done := make(chan struct{})
	p.attach.Lock()
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
	p.cancel, p.done = cancel, done
	p.attach.Unlock()
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-p.closed:
			cancel()
		}
	}()
	// Decoder epoch reset is explicit: a partial UDP packet cannot span sockets.
	decoder, encoder := cell.NewDecoder(), cell.NewEncoder(nil)
	defer encoder.Abort()
	for {
		typ, frame, err := ws.Read(ctx)
		if err != nil || typ != websocket.MessageBinary || len(frame) < profile.MinSize || len(frame) > profile.MaxSize {
			return
		}
		packets, err := decoder.Accept(frame)
		if err != nil {
			return
		}
		for _, packet := range packets {
			if err := p.udp.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			if _, err := p.udp.Write(packet); err != nil {
				return
			}
		}
		// Never await a target response: shape depends on the poll, not IWP latency.
		for n := 0; n < cell.MaxPending; n++ {
			select {
			case packet := <-p.incoming:
				_ = encoder.Push(packet) // bounded UDP loss under overload
			default:
				n = cell.MaxPending
			}
		}
		replySize := len(frame)
		if profile.ReplyMinSize != 0 {
			replySize, err = randomRange(profile.ReplyMinSize, profile.ReplyMaxSize)
			if err != nil {
				return
			}
		}
		reply, err := encoder.Next(replySize)
		if err != nil || writeUDPFrame(ctx, ws, websocket.MessageBinary, reply) != nil {
			return
		}
	}
}

func relayCells(parent context.Context, listener *net.UDPConn, peer *udpPeer, ws *websocket.Conn, encoder *cell.Encoder, profile cellProfile, trace *clientTrace) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer encoder.Abort()
	decoder := cell.NewDecoder()
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-peer.queue:
				_ = encoder.Push(packet)
			}
		}
	}()
	defer func() { cancel(); ws.CloseNow(); <-producerDone }()
	cycles := 0
	for {
		started := time.Now()
		burst := max(1, profile.BurstCells)
		sizes := make([]int, burst)
		totalBytes := 0
		for i := range burst {
			size, err := profile.size()
			if err != nil {
				return err
			}
			sizes[i] = size
			totalBytes += size
			frame, err := encoder.Next(size)
			if err != nil {
				return err
			}
			if err := writeUDPFrame(ctx, ws, websocket.MessageBinary, frame); err != nil {
				return err
			}
		}
		for i := range burst {
			readCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			typ, reply, err := ws.Read(readCtx)
			stop()
			if err != nil {
				return err
			}
			validSize := len(reply) == sizes[i]
			if profile.ReplyMinSize != 0 {
				validSize = len(reply) >= profile.ReplyMinSize && len(reply) <= profile.ReplyMaxSize
			}
			if typ != websocket.MessageBinary || !validSize {
				return errors.New("invalid cell reply")
			}
			packets, err := decoder.Accept(reply)
			if err != nil {
				return err
			}
			for _, packet := range packets {
				trace.downBytes.Add(uint64(len(packet)))
				trace.downDatagrams.Add(1)
				if _, err := listener.WriteToUDP(packet, peer.addr); err != nil {
					return err
				}
			}
		}
		delay, err := profile.delay(totalBytes)
		if err != nil {
			return err
		}
		cycles++
		if profile.PauseEvery > 0 && cycles%profile.PauseEvery == 0 {
			delay += time.Duration(profile.PauseMS) * time.Millisecond
		}
		delay -= time.Since(started)
		if delay > 0 && !waitUDPReconnect(ctx, delay) {
			return ctx.Err()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

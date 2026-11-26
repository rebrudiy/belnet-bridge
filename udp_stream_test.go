package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rebrudiy/belnet-bridge/internal/streamframe"
)

func streamTestServer(t *testing.T, target *net.UDPAddr) (*streamBridge, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := newStreamBridge(target, "unit-secret", 8, &streamMetrics{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		l.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("stream server did not drain")
		}
	})
	return b, l
}

func streamTestDial(t *testing.T, address string, sid [32]byte) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := streamframe.WriteHandshake(c, sid, "unit-secret"); err != nil {
		t.Fatal(err)
	}
	if err := streamframe.ReadAccepted(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStreamRetainsTupleAndExactUDPOnAttachmentReplacement(t *testing.T) {
	target := udpSocket(t)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, maxUDPDatagram)
		for {
			n, a, e := target.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if _, e = target.WriteToUDP(buf[:n], a); e != nil {
				return
			}
		}
	}()
	defer func() { target.Close(); <-echoDone }()
	b, l := streamTestServer(t, target.LocalAddr().(*net.UDPAddr))
	sid := [32]byte{1}
	first := streamTestDial(t, l.Addr().String(), sid)
	exchange := func(c net.Conn, payload []byte) {
		t.Helper()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if err := streamframe.Write(c, payload); err != nil {
			t.Fatal(err)
		}
		got, err := streamframe.Read(c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, got) {
			t.Fatalf("UDP %d became %d bytes", len(payload), len(got))
		}
	}
	sizes := []int{0, 1, 1200, 8192}
	if runtime.GOOS != "darwin" {
		sizes = append(sizes, 60000, 65507)
	}
	for _, n := range sizes {
		exchange(first, bytes.Repeat([]byte{byte(n % 251)}, n))
	}
	getTuple := func(hash string) string {
		state := b.metrics.state()
		for _, c := range state["connections"].([]streamConnectionState) {
			if c.SessionHash == hash && c.Connected {
				return c.UDPTuple
			}
		}
		t.Fatal("missing active tuple")
		return ""
	}
	before := getTuple(sessionHash(sid[:]))
	second := streamTestDial(t, l.Addr().String(), sid)
	exchange(second, []byte("same native session"))
	if after := getTuple(sessionHash(sid[:])); after != before {
		t.Fatalf("tuple changed: %s -> %s", before, after)
	}
	first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := streamframe.Read(first); err == nil {
		t.Fatal("old attachment remained live")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("old attachment was idle, not closed")
		}
	}
	otherSID := [32]byte{2}
	other := streamTestDial(t, l.Addr().String(), otherSID)
	exchange(other, []byte("isolated"))
	if getTuple(sessionHash(otherSID[:])) == before {
		t.Fatal("distinct SID reused UDP tuple")
	}
}

func TestStreamRejectsTokenBeforeUDPStateAndTerminalClose(t *testing.T) {
	target := udpSocket(t)
	b, l := streamTestServer(t, target.LocalAddr().(*net.UDPAddr))
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if err := streamframe.WriteHandshake(c, [32]byte{3}, "bad-secret"); err != nil {
		t.Fatal(err)
	}
	if streamframe.ReadAccepted(c) == nil {
		t.Fatal("bad token accepted")
	}
	b.bridge.sessionsMu.Lock()
	n := len(b.bridge.sessions)
	b.bridge.sessionsMu.Unlock()
	if n != 0 {
		t.Fatal("bad token allocated native UDP state")
	}
	b.bridge.Close()
	if _, err := b.bridge.resumed("after-close"); err == nil {
		t.Fatal("terminal store close permitted late UDP creation")
	}
}

func TestStreamClientCancelInterruptsHandshake(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 1)
	handshakeErr := make(chan error, 1)
	go func() {
		c, e := upstream.Accept()
		if e != nil {
			handshakeErr <- e
			return
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, _, e = streamframe.ReadHandshake(c)
		if e != nil {
			c.Close()
			handshakeErr <- e
			return
		}
		accepted <- c
	}()
	local := udpSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runUDPStreamProxy(ctx, local, upstream.Addr().String(), "unit-secret", nil) }()
	source, err := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	source.Write([]byte("queued"))
	var conn net.Conn
	select {
	case conn = <-accepted:
	case err := <-handshakeErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("client did not connect")
	}
	defer conn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancel waited for handshake deadline")
	}
}

func TestStreamPayloadHasSeparateShortTransferDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { var header [4]byte; binary.BigEndian.PutUint32(header[:], 10); _, _ = client.Write(header[:]) }()
	started := time.Now()
	_, err := readStreamDatagram(server, time.Second, 25*time.Millisecond)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected body timeout, got %v", err)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("body inherited idle/header deadline")
	}
}

type failAfterAccept struct {
	net.Listener
	calls atomic.Int32
}

func (l *failAfterAccept) Accept() (net.Conn, error) {
	if l.calls.Add(1) > 1 {
		return nil, errors.New("unit accept failure")
	}
	return l.Listener.Accept()
}

func TestStreamAcceptErrorClosesPendingHandlers(t *testing.T) {
	target := udpSocket(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	b := newStreamBridge(target.LocalAddr().(*net.UDPAddr), "unit-secret", 8, nil)
	done := make(chan error, 1)
	go func() { done <- b.serve(context.Background(), &failAfterAccept{Listener: raw}) }()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accept error vanished")
		}
	case <-time.After(time.Second):
		t.Fatal("accept failure left worker blocked")
	}
	b.bridge.sessionsMu.Lock()
	defer b.bridge.sessionsMu.Unlock()
	if !b.bridge.closed || len(b.bridge.sessions) != 0 {
		t.Fatal("server did not close session store")
	}
}

func TestStreamLoopbackOnly(t *testing.T) {
	for _, address := range []string{"0.0.0.0:21990", "localhost:21990", "10.88.0.11:21990", "[::]:21990"} {
		if literalLoopback(address) == nil {
			t.Fatalf("unsafe plaintext endpoint accepted: %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1:21990", "[::1]:21990"} {
		if err := literalLoopback(address); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamProxyReconnectKeepsNativeUDPTuple(t *testing.T) {
	target := udpSocket(t)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, maxUDPDatagram)
		for {
			n, a, e := target.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if _, e = target.WriteToUDP(buf[:n], a); e != nil {
				return
			}
		}
	}()
	defer func() { target.Close(); <-echoDone }()
	b, server := streamTestServer(t, target.LocalAddr().(*net.UDPAddr))
	local := udpSocket(t)
	metrics := &streamMetrics{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runUDPStreamProxy(ctx, local, server.Addr().String(), "unit-secret", metrics) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("proxy failed to drain")
		}
	}()
	source, err := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	exchange := func(payload string) {
		t.Helper()
		source.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := source.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := source.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != payload {
			t.Fatal("payload corrupted across reconnect")
		}
	}
	exchange("before")
	before := b.metrics.state()["connections"].([]streamConnectionState)[0]
	b.mu.Lock()
	for conn := range b.connections {
		conn.Close()
	}
	b.mu.Unlock()
	exchange("after")
	after := b.metrics.state()["connections"].([]streamConnectionState)
	if len(after) != 2 || after[1].SessionHash != before.SessionHash || after[1].UDPTuple != before.UDPTuple {
		t.Fatal("outer TCP reset changed native identity/tuple")
	}
	state := metrics.state()
	inputs := state["udp_inputs"].([]streamInputEvent)
	if len(inputs) != 2 || !inputs[0].Accepted || !inputs[1].Accepted {
		t.Fatal("missing real native input counters")
	}
	for _, event := range state["packet_events"].([]streamPacketEvent) {
		if event.Direction > 0 && (event.InputUnixMicros <= 0 || event.WriteStartedUnixMicros < event.InputUnixMicros || event.AtUnixMicros < event.WriteStartedUnixMicros) {
			t.Fatal("invalid queue/write timestamp ordering")
		}
	}
}

func TestStreamUDPSocketDeathClosesAttachment(t *testing.T) {
	target := udpSocket(t)
	b, l := streamTestServer(t, target.LocalAddr().(*net.UDPAddr))
	c := streamTestDial(t, l.Addr().String(), [32]byte{9})
	b.bridge.sessionsMu.Lock()
	for _, p := range b.bridge.sessions {
		p.udp.Close()
	}
	b.bridge.sessionsMu.Unlock()
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err := streamframe.Read(c)
	if err == nil {
		t.Fatal("dead UDP socket retained stream")
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("dead UDP stream did not close promptly")
	}
}

func TestStreamMaxAgeDropsStaleButRetainModePreservesIt(t *testing.T) {
	for _, limit := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(limit.String(), func(t *testing.T) {
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			acknowledged := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				c, e := upstream.Accept()
				if e != nil {
					serverDone <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, _, e = streamframe.ReadHandshake(c); e != nil {
					serverDone <- e
					return
				}
				time.Sleep(300 * time.Millisecond)
				if e = streamframe.WriteAccepted(c); e != nil {
					serverDone <- e
					return
				}
				close(acknowledged)
				for {
					p, e := streamframe.Read(c)
					if e != nil {
						serverDone <- e
						return
					}
					if e = streamframe.Write(c, p); e != nil {
						serverDone <- e
						return
					}
					if string(p) == "fresh" {
						serverDone <- nil
						return
					}
				}
			}()
			local := udpSocket(t)
			metrics := &streamMetrics{}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- runUDPStreamProxyWithMaxAge(ctx, local, upstream.Addr().String(), "unit-secret", metrics, limit)
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("expiry proxy failed to drain")
				}
			}()
			source, e := net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
			if e != nil {
				t.Fatal(e)
			}
			defer source.Close()
			source.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = source.Write([]byte("stale")); e != nil {
				t.Fatal(e)
			}
			select {
			case <-acknowledged:
			case e := <-serverDone:
				t.Fatal(e)
			case <-time.After(time.Second):
				t.Fatal("handshake not acknowledged")
			}
			if _, e = source.Write([]byte("fresh")); e != nil {
				t.Fatal(e)
			}
			want := []string{"fresh"}
			if limit == 0 {
				want = []string{"stale", "fresh"}
			}
			for _, message := range want {
				buf := make([]byte, 64)
				n, e := source.Read(buf)
				if e != nil {
					t.Fatal(e)
				}
				if string(buf[:n]) != message {
					t.Fatalf("expected %q, got %q", message, buf[:n])
				}
			}
			if e := <-serverDone; e != nil {
				t.Fatal(e)
			}
			state := metrics.state()
			expired := state["expired_events"].([]streamExpiredEvent)
			if limit == 0 && len(expired) != 0 {
				t.Fatal("default retain lost queued packet")
			}
			if limit > 0 {
				if len(expired) != 1 || expired[0].Bytes != 5 || expired[0].AgeMicros <= limit.Microseconds() {
					t.Fatal("stale input not explicitly accounted")
				}
				for _, p := range state["packet_events"].([]streamPacketEvent) {
					if p.Direction > 0 && p.QueueWaitMicros > limit.Microseconds() {
						t.Fatal("expired packet reached stream write")
					}
				}
			}
			inputs := state["udp_inputs"].([]streamInputEvent)
			if len(inputs) != 2 {
				t.Fatal("expiry hid original native input")
			}
			var allAge int64
			for _, c := range state["connections"].([]streamConnectionState) {
				allAge = max(allAge, c.MaxAllInputAgeMicros)
			}
			if allAge < 100000 {
				t.Fatal("all-input age lost the stalled interval")
			}
		})
	}
}

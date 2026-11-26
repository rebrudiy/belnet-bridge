package main

import (
	"bytes"
	"context"
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rebrudiy/belnet-bridge/internal/cell"
)

func TestCellsCarryCompleteUDPAndCancel(t *testing.T) {
	for _, profile := range []cellProfile{
		{Name: "paired", MinSize: 256, MaxSize: 1536, IntervalMS: 2, JitterMS: 2},
		{Name: "burst-asymmetric", MinSize: 384, MaxSize: 3072, IntervalMS: 2, JitterMS: 4, BurstCells: 4, ReplyMinSize: 256, ReplyMaxSize: 2048},
		{Name: "mixture", MinSize: 256, MaxSize: 4096, IntervalMS: 2, JitterMS: 2, SizeMode: "mixture", DelayMode: "exponential", BurstCells: 2, PauseEvery: 8, PauseMS: 5},
	} {
		t.Run(profile.Name, func(t *testing.T) {
			target := udpSocket(t)
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				buf := make([]byte, maxUDPDatagram)
				for {
					n, addr, err := target.ReadFromUDP(buf)
					if err != nil {
						return
					}
					if _, err = target.WriteToUDP(buf[:n], addr); err != nil {
						return
					}
				}
			}()
			defer func() { target.Close(); <-echoDone }()
			bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "test-token", "/ws", 8)
			defer bridge.Close()
			server := httptest.NewTLSServer(bridge)
			defer server.Close()
			listener := udpSocket(t)
			lab := newClientLab("")
			lab.epoch.Cells = &profile
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- runUDPProxyWithLab(ctx, listener, "wss"+strings.TrimPrefix(server.URL, "https")+"/ws", "test-token", server.Client(), lab)
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("cell relay did not cancel")
				}
			}()
			source, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			sizes := []int{0, 1, 1200, 8192}
			// Darwin's default udp.maxdgram is 9216. The codec always tests the
			// full UDP limit; the real UDP socket path also runs on lab Linux.
			if runtime.GOOS != "darwin" {
				sizes = append(sizes, 60000, 65507)
			}
			for _, size := range sizes {
				payload := bytes.Repeat([]byte{byte(size % 251)}, size)
				if err := source.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := source.Write(payload); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, maxUDPDatagram)
				n, err := source.Read(buf)
				if err != nil {
					t.Fatalf("size%d: %v", size, err)
				}
				if !bytes.Equal(payload, buf[:n]) {
					t.Fatalf("size%d returned %d corrupted bytes", size, n)
				}
			}
		})
	}
}

func TestCellsCannotRemainConnectedAfterUDPSocketCloses(t *testing.T) {
	target := udpSocket(t)
	bridge := NewUDPBridge(target.LocalAddr().(*net.UDPAddr), "secret", "/ws", 8)
	defer bridge.Close()
	server := httptest.NewTLSServer(bridge)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	profile := cellProfile{Name: "x", MinSize: 256, MaxSize: 256, IntervalMS: 10}
	h, err := cellHeaders("secret", strings.Repeat("a", 64), profile, "/ws")
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https")+"/ws", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	dummy, err := cell.NewEncoder(nil).Next(256)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Write(ctx, websocket.MessageBinary, dummy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ws.Read(ctx); err != nil {
		t.Fatal(err)
	}
	bridge.Close()
	if _, _, err := ws.Read(ctx); err == nil {
		t.Fatal("WS remained alive after UDP association closed")
	}
}

func TestCellProfileRejectsUnboundedModes(t *testing.T) {
	base := cellProfile{Name: "x", MinSize: 256, MaxSize: 8192, IntervalMS: 10}
	for _, mutate := range []func(*cellProfile){func(p *cellProfile) { p.BurstCells = 9 }, func(p *cellProfile) { p.ReplyMinSize = 256 }, func(p *cellProfile) { p.PauseMS = 2001 }, func(p *cellProfile) { p.SizeMode = "pretend-https" }} {
		p := base
		mutate(&p)
		if p.Validate() == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}

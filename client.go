package main

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/coder/websocket"
)

// Dial connects to a bridge and returns the tunnel address the server assigned.
func Dial(ctx context.Context, url, token string, httpClient *http.Client) (*websocket.Conn, netip.Prefix, netip.Addr, error) {
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPClient:      httpClient,
		HTTPHeader:      http.Header{"Authorization": {"Bearer " + token}},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, netip.Prefix{}, netip.Addr{}, err
	}
	ws.SetReadLimit(mtu + 100)
	_, msg, err := ws.Read(ctx)
	if err != nil {
		ws.CloseNow()
		return nil, netip.Prefix{}, netip.Addr{}, err
	}
	addr, gw, err := parseHello(string(msg))
	if err != nil {
		ws.CloseNow()
		return nil, netip.Prefix{}, netip.Addr{}, fmt.Errorf("bad hello %q: %w", msg, err)
	}
	return ws, addr, gw, nil
}

// Relay moves packets between the local TUN device and the bridge until one side fails.
func Relay(ctx context.Context, dev Device, ws *websocket.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- devToWS(ctx, dev, ws) }()
	go func() {
		for {
			_, pkt, err := ws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if _, err := dev.Write(pkt); err != nil {
				errc <- err
				return
			}
		}
	}()
	return <-errc
}

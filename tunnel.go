package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/coder/websocket"
)

// Device is a TUN interface: every Read returns one IP packet, every Write takes one.
type Device interface {
	io.ReadWriteCloser
}

const mtu = 1400

// dstIPv4 returns the destination address of an IPv4 packet.
func dstIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[16:20])), true
}

// srcIPv4 returns the source address of an IPv4 packet.
func srcIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), true
}

// devToWS copies packets from the device to the websocket until either side fails.
func devToWS(ctx context.Context, dev io.Reader, ws *websocket.Conn) error {
	buf := make([]byte, mtu+100)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			return err
		}
		if err := ws.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
			return err
		}
	}
}

// IPPool hands out one tunnel address per connected client.
type IPPool struct {
	mu     sync.Mutex
	prefix netip.Prefix
	used   map[netip.Addr]bool
}

func NewIPPool(prefix netip.Prefix) *IPPool {
	return &IPPool{prefix: prefix.Masked(), used: map[netip.Addr]bool{}}
}

// Gateway is the server's own address: the first host in the prefix.
func (p *IPPool) Gateway() netip.Addr { return p.prefix.Addr().Next() }

func (p *IPPool) Acquire() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for a := p.Gateway().Next(); p.prefix.Contains(a); a = a.Next() {
		if isBroadcast(p.prefix, a) {
			break
		}
		if !p.used[a] {
			p.used[a] = true
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("address pool exhausted")
}

func (p *IPPool) Release(a netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, a)
}

func isBroadcast(prefix netip.Prefix, a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	ip := binary.BigEndian.Uint32(a.AsSlice())
	hostBits := 32 - prefix.Bits()
	return hostBits > 0 && ip&(1<<hostBits-1) == 1<<hostBits-1
}

// hello is the first websocket message from server to client: "<client-ip>/<bits> <gateway>".
func hello(client netip.Addr, prefix netip.Prefix, gw netip.Addr) string {
	return fmt.Sprintf("%s/%d %s", client, prefix.Bits(), gw)
}

func parseHello(s string) (client netip.Prefix, gw netip.Addr, err error) {
	var cs, gs string
	if _, err = fmt.Sscan(s, &cs, &gs); err != nil {
		return
	}
	if client, err = netip.ParsePrefix(cs); err != nil {
		return
	}
	gw, err = netip.ParseAddr(gs)
	return
}

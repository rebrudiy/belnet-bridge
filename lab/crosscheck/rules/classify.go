package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/blake2b"
)

func writeVerdict(f *os.File, reason string) {
	b, _ := json.Marshal(map[string]any{
		"ts":      time.Now().UnixNano(),
		"verdict": "drop",
		"reason":  reason,
	})
	f.Write(append(b, '\n'))
}

// classify parses an IPv4 packet and returns whether to DROP it and why.
// Non-UDP and unparseable packets are always accepted (TLS/WebSocket to the
// bridge must pass).
func (c *classifier) classify(pkt []byte) (bool, string) {
	src, dst, payload, ok := parseUDP(pkt)
	if !ok {
		return false, ""
	}

	if c.cfg.detect["iplist"] {
		for _, r := range c.cfg.relays {
			if r.Contains(dst.Addr()) || r.Contains(src.Addr()) {
				return true, "iplist"
			}
		}
	}
	if c.cfg.detect["crypto"] && isIWPIntro(payload, c.cfg.keys) {
		return true, "crypto"
	}
	if c.cfg.detect["size"] && c.sizeMatch(src, dst, payload) {
		return true, "size"
	}
	if c.cfg.detect["entropy"] && looksEncrypted(payload) {
		return true, "entropy"
	}
	if c.cfg.throttle > 0 && len(payload) > 0 && rand.Float64() < c.cfg.throttle {
		return true, "throttle"
	}
	return false, ""
}

// parseUDP extracts src/dst addrport and UDP payload from an IPv4 packet.
func parseUDP(pkt []byte) (src, dst netip.AddrPort, payload []byte, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 17 { // proto 17 = UDP
		return
	}
	sa := netip.AddrFrom4([4]byte(pkt[12:16]))
	da := netip.AddrFrom4([4]byte(pkt[16:20]))
	sport := int(pkt[ihl])<<8 | int(pkt[ihl+1])
	dport := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
	payload = pkt[ihl+8:]
	return netip.AddrPortFrom(sa, uint16(sport)), netip.AddrPortFrom(da, uint16(dport)), payload, true
}

// sizeMatch recognises the IWP handshake by its first-datagram sizes: the
// client's first datagram to a router is exactly 224 bytes, the first replies
// 88 bytes (belnet-internals.md §2, verified in 7/7 captured flows).
func (c *classifier) sizeMatch(src, dst netip.AddrPort, payload []byte) bool {
	n := len(payload)
	// fast path: the very first client datagram is a dead giveaway.
	if n == 224 {
		return true
	}
	key := src.String() + ">" + dst.String()
	c.mu.Lock()
	fs := c.flows[key]
	if fs == nil {
		fs = &flowState{}
		c.flows[key] = fs
		if len(c.flows) > 100000 {
			c.flows = map[string]*flowState{} // bound memory
		}
	}
	if fs.n < 4 {
		fs.sizes = append(fs.sizes, n)
		fs.n++
	}
	sizes := append([]int(nil), fs.sizes...)
	c.mu.Unlock()
	// 224 then 88 then 88 is the full intro signature.
	if len(sizes) >= 2 && sizes[0] == 224 && sizes[1] == 88 {
		return true
	}
	return false
}

// isIWPIntro checks whether payload is an IWP intro for one of the relay keys:
// keyed-BLAKE2b(key=BLAKE2b256(relayPubKey), data=payload[32:]) == payload[:32].
// With the lab's own relay keys this is a zero-false-positive oracle.
func isIWPIntro(payload []byte, keys [][]byte) bool {
	if len(payload) < 33 {
		return false
	}
	mac := payload[:32]
	body := payload[32:]
	for _, pub := range keys {
		kk := blake2b.Sum256(pub)
		h, err := blake2b.New256(kk[:])
		if err != nil {
			continue
		}
		h.Write(body)
		if ctEqual(h.Sum(nil), mac) {
			return true
		}
	}
	return false
}

func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// looksEncrypted flags UDP payloads in the LLARP size range whose bytes are
// statistically indistinguishable from random (Shannon entropy per byte near 8
// bits and no long ASCII runs). Mirrors fully-encrypted-traffic detection.
func looksEncrypted(payload []byte) bool {
	if len(payload) < 64 || len(payload) > 1400 {
		return false
	}
	var counts [256]int
	ascii := 0
	for _, b := range payload {
		counts[b]++
		if b >= 0x20 && b < 0x7f {
			ascii++
		}
	}
	if float64(ascii)/float64(len(payload)) > 0.5 { // lots of printable -> not encrypted
		return false
	}
	ent := 0.0
	n := float64(len(payload))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent > 7.0 // close to the 8.0 maximum
}

func loadKeys(file string) [][]byte {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	var keys [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		b, err := hex.DecodeString(trimSpace(line))
		if err == nil && len(b) == 32 {
			keys = append(keys, b)
		}
	}
	return keys
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (c *classifier) record(dropped bool, reason string) {
	c.mu.Lock()
	c.seen++
	if dropped {
		c.dropped++
	}
	c.mu.Unlock()
	if c.logf != nil && dropped {
		writeVerdict(c.logf, reason)
	}
}

func signalCtx() context.Context {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	_ = cancel
	return ctx
}

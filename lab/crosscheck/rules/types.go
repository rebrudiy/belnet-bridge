package main

import (
	"net/netip"
	"os"
	"sync"
)

type config struct {
	queue    uint16
	detect   map[string]bool
	relays   []netip.Prefix
	keys     [][]byte // relay identity public keys (32B each) for the crypto tier
	throttle float64
	logPath  string
}

type classifier struct {
	cfg   *config
	mu    sync.Mutex
	flows map[string]*flowState // src:sport->dst:dport first-packet sizing
	logf  *os.File
	// counters
	seen, dropped uint64
}

type flowState struct {
	sizes []int
	n     int
}

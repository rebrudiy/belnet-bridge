// Package bench supplies bounded synthetic application workloads for both a
// legitimate TLS/WSS backend and a native .bdx HTTP service. It is not echo.
package bench

import (
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"time"
)

const MaxDuration = 80 * time.Second
const DefaultBudget = 4 * 1024 * 1024

var Families = []string{"download", "upload", "rpc", "push", "chat", "idle"}

type Action struct {
	AtMS  int64  `json:"at_ms"`
	Bytes int    `json:"bytes"`
	Seq   int    `json:"seq"`
	Kind  string `json:"kind"`
}
type Response struct {
	Bytes   int `json:"bytes"`
	DelayMS int `json:"delay_ms"`
}
type Plan struct {
	Family     string     `json:"family"`
	Seed       int64      `json:"seed"`
	DurationMS int64      `json:"duration_ms"`
	Up         []Action   `json:"up"`
	Down       []Action   `json:"down"`
	RPC        []Response `json:"rpc,omitempty"`
	UpBytes    int        `json:"up_bytes"`
	DownBytes  int        `json:"down_bytes"`
}

func NewPlan(family string, seed int64, duration time.Duration, budget int) (Plan, error) {
	p := Plan{Family: family, Seed: seed, DurationMS: duration.Milliseconds(), Up: []Action{}, Down: []Action{}}
	known := false
	for _, f := range Families {
		known = known || f == family
	}
	if !known || seed < 1 || seed > 1<<48-1 || duration < 10*time.Millisecond || duration > MaxDuration || budget < 32768 || budget > 16*1024*1024 {
		return p, errors.New("invalid bounded workload")
	}
	if family == "idle" {
		return p, nil
	}
	rng := rand.New(rand.NewSource(seed))
	makeActions := func(direction string, minSize, maxSize, minGap, maxGap int, kind string) {
		at, seq, total := int64(0), 0, 0
		for at < p.DurationMS {
			size := minSize + rng.Intn(maxSize-minSize+1)
			if total+size > budget {
				break
			}
			a := Action{at, size, seq, kind}
			if direction == "up" {
				p.Up = append(p.Up, a)
				p.UpBytes += size
			} else {
				p.Down = append(p.Down, a)
				p.DownBytes += size
			}
			total += size
			seq++
			at += int64(minGap + rng.Intn(maxGap-minGap+1))
		}
	}
	switch family {
	case "download":
		makeActions("down", 4096, 32768, 70, 260, "binary")
	case "upload":
		makeActions("up", 4096, 16384, 40, 160, "binary")
		makeActions("down", 256, 384, 500, 1300, "upload-ack")
	case "rpc":
		makeActions("up", 256, 1024, 150, 700, "rpc-request")
		for range p.Up {
			size := 384 + rng.Intn(3713)
			if p.DownBytes+size > budget {
				break
			}
			p.RPC = append(p.RPC, Response{size, 20 + rng.Intn(101)})
			p.DownBytes += size
		}
		p.Up = p.Up[:len(p.RPC)]
		p.UpBytes = 0
		for _, a := range p.Up {
			p.UpBytes += a.Bytes
		}
	case "push":
		makeActions("down", 256, 2048, 80, 450, "push-event")
	case "chat":
		makeActions("up", 256, 1024, 250, 1800, "chat-client")
		makeActions("down", 256, 1536, 300, 1600, "chat-server")
	}
	return p, nil
}

// Payload uses independent server/client message kinds and sequence-derived
// content. JSON responses are generated independently from received bytes.
func Payload(kind string, seq, size int, seed int64, fields map[string]any) ([]byte, error) {
	if size < 1 || size > 32768 {
		return nil, errors.New("invalid message size")
	}
	if kind == "binary" {
		p := make([]byte, size)
		for i := range p {
			p[i] = byte((seed%251 + int64(seq)*131 + int64(i)*17) % 251)
		}
		return p, nil
	}
	m := map[string]any{"kind": kind, "seq": seq}
	for k, v := range fields {
		m[k] = v
	}
	m["padding"] = ""
	base, err := json.Marshal(m)
	if err != nil || len(base) > size {
		return nil, errors.New("message metadata exceeds target size")
	}
	m["padding"] = strings.Repeat("x", size-len(base))
	return json.Marshal(m)
}

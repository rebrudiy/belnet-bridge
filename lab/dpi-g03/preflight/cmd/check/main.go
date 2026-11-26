package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type conn struct {
	ID        uint64 `json:"id"`
	SID       string `json:"session_hash"`
	UDP       string `json:"udp_tuple"`
	Connected bool   `json:"connected"`
}
type state struct {
	Connections []conn `json:"connections"`
	Truncated   bool   `json:"metadata_truncated"`
}

func main() {
	if len(os.Args) != 2 {
		panic("echo|probe")
	}
	if os.Args[1] == "echo" {
		echo()
		return
	}
	if e := probe(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func echo() {
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12092})
	if e != nil {
		panic(e)
	}
	defer c.Close()
	b := make([]byte, 65535)
	for {
		n, p, e := c.ReadFromUDP(b)
		if e != nil {
			return
		}
		h := sha256.Sum256(b[:n])
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"at_unix_micros": time.Now().UnixMicro(), "bytes": n, "peer": p.String(), "sha256": hex.EncodeToString(h[:])})
		_, _ = c.WriteToUDP(b[:n], p)
	}
}
func snapshot(name string) (state, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	r, e := client.Get("http://127.0.0.1:2293/state")
	if e != nil {
		return state{}, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if e != nil {
		return state{}, e
	}
	if e = os.WriteFile("/work/"+name+".json", b, 0600); e != nil {
		return state{}, e
	}
	var s state
	e = json.Unmarshal(b, &s)
	if r.StatusCode != 200 {
		return s, fmt.Errorf("state_status_%d", r.StatusCode)
	}
	return s, e
}
func pairs(s state) map[string]string {
	m := map[string]string{}
	for _, c := range s.Connections {
		if c.SID != "" && c.UDP != "" {
			m[c.SID] = c.UDP
		}
	}
	return m
}
func same(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func probe() (ret error) {
	result := map[string]any{"dev_only": true, "excluded_from_B": true, "native_belnet": false, "started_unix_micros": time.Now().UnixMicro(), "retry_until_success": false}
	attempts := []map[string]any{}
	errors := []string{}
	defer func() {
		result["finished_unix_micros"] = time.Now().UnixMicro()
		result["attempts"] = attempts
		result["errors"] = errors
		if ret != nil {
			result["error"] = ret.Error()
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile("/work/result.json", append(b, '\n'), 0600)
		_ = json.NewEncoder(os.Stdout).Encode(result)
	}()
	time.Sleep(3 * time.Second) // one fixed startup interval; no polling/reroll of payload tests
	source, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2093})
	if e != nil {
		return e
	}
	defer source.Close()
	result["primary_source"] = source.LocalAddr().String()
	for _, n := range []int{0, 1, 1200} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte((i*29 + n) % 251)
		}
		sum := sha256.Sum256(b)
		a := map[string]any{"kind": "valid_token", "bytes": n, "sha256": hex.EncodeToString(sum[:]), "started_unix_micros": time.Now().UnixMicro()}
		_ = source.SetDeadline(time.Now().Add(5 * time.Second))
		_, e := source.Write(b)
		read := make([]byte, 65535)
		m := 0
		if e == nil {
			m, e = source.Read(read)
		}
		a["finished_unix_micros"] = time.Now().UnixMicro()
		a["exact"] = e == nil && bytes.Equal(b, read[:m])
		a["received_bytes"] = m
		if e != nil {
			a["error"] = e.Error()
		}
		attempts = append(attempts, a)
		if a["exact"] != true {
			errors = append(errors, fmt.Sprintf("valid_payload_%d_failed", n))
		}
	}
	before, e := snapshot("before-invalid")
	if e != nil {
		return e
	}
	beforePairs := pairs(before)
	result["valid_session_count"] = len(beforePairs)
	if len(beforePairs) != 1 || before.Truncated {
		errors = append(errors, "valid_server_state_incomplete")
	}
	for _, x := range []struct {
		kind string
		port int
	}{{"invalid_token", 2094}, {"forbidden_destination", 2095}} {
		c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: x.port})
		if e != nil {
			return e
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		start := time.Now().UnixMicro()
		_, e = c.Write([]byte("fixed-negative-fixture"))
		b := make([]byte, 128)
		n := 0
		if e == nil {
			n, e = c.Read(b)
		}
		c.Close()
		timeout := false
		if ne, ok := e.(net.Error); ok {
			timeout = ne.Timeout()
		}
		attempts = append(attempts, map[string]any{"kind": x.kind, "started_unix_micros": start, "finished_unix_micros": time.Now().UnixMicro(), "received_bytes": n, "blocked": timeout})
		if !timeout {
			errors = append(errors, x.kind+"_unexpected_delivery_or_error")
		}
	}
	after, e := snapshot("after-invalid")
	if e != nil {
		return e
	}
	result["bad_cases_create_no_udp_state"] = same(beforePairs, pairs(after)) && !after.Truncated
	if !result["bad_cases_create_no_udp_state"].(bool) {
		errors = append(errors, "invalid_cases_changed_UDP_state")
	}
	result["passed"] = len(errors) == 0
	if len(errors) > 0 {
		return fmt.Errorf("%d failed assertions", len(errors))
	}
	return nil
}

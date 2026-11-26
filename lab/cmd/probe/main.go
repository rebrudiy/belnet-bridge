package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: probe rc-id FILE | serve | fetch URL")
	}
	switch os.Args[1] {
	case "udp-echo":
		udpEcho()
	case "udp-check":
		udpCheck()
	case "report":
		report()
	case "tick":
		tick()
	case "rc-id", "rc-key":
		if len(os.Args) != 3 {
			log.Fatal("rc-id needs FILE")
		}
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		p := 0
		value, err := decode(data, &p)
		if err != nil {
			log.Fatal(err)
		}
		if list, ok := value.([]any); ok && len(list) == 3 {
			value = list[2]
		}
		m, ok := value.(map[string]any)
		if !ok {
			log.Fatal("RC has no dictionary")
		}
		key, ok := m["k"].([]byte)
		if !ok || len(key) != 32 {
			log.Fatal("RC has no 32-byte public identity")
		}
		if os.Args[1] == "rc-key" {
			fmt.Println(hex.EncodeToString(key))
			return
		}
		fmt.Println(base32.NewEncoding("ybndrfg8ejkmcpqxot1uwisza345h769").WithPadding(base32.NoPadding).EncodeToString(key) + ".mnode")
	case "serve":
		http.HandleFunc("/proof", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method", 405)
				return
			}
			nonce := r.URL.Query().Get("nonce")
			if len(nonce) != 32 {
				http.Error(w, "nonce", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce, "service": "bb-lab-service", "time": time.Now().UTC().Format(time.RFC3339Nano)})
			log.Printf("proof nonce=%s remote=%s", nonce, r.RemoteAddr)
		})
		server := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second, Handler: http.DefaultServeMux}
		log.Fatal(server.ListenAndServe())
	case "fetch":
		if len(os.Args) != 3 {
			log.Fatal("fetch needs URL")
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			log.Fatal(err)
		}
		nonce := hex.EncodeToString(random[:])
		url := strings.TrimRight(os.Args[2], "/") + "/proof?nonce=" + nonce
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", "127.3.2.1:53")
		}}
		transport := &http.Transport{DialContext: (&net.Dialer{Resolver: resolver}).DialContext, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
		start := time.Now()
		resp, err := client.Get(url)
		result := map[string]any{"time": start.UTC().Format(time.RFC3339Nano), "nonce": nonce, "url": url}
		if err != nil {
			result["error"] = err.Error()
			result["ok"] = false
			result["elapsed_ms"] = time.Since(start).Milliseconds()
			_ = json.NewEncoder(os.Stdout).Encode(result)
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			log.Fatal(err)
		}
		var proof map[string]string
		parseErr := json.Unmarshal(body, &proof)
		ok := parseErr == nil && resp.StatusCode == 200 && proof["nonce"] == nonce && proof["service"] == "bb-lab-service"
		result["status"] = resp.StatusCode
		result["body"] = string(body)
		result["ok"] = ok
		result["elapsed_ms"] = time.Since(start).Milliseconds()
		_ = json.NewEncoder(os.Stdout).Encode(result)
		if !ok {
			os.Exit(1)
		}
	default:
		log.Fatal("unknown command")
	}
}

// decode parses only the standard bencode types used by RouterContact files.
func decode(b []byte, p *int) (any, error) {
	if *p >= len(b) {
		return nil, io.ErrUnexpectedEOF
	}
	c := b[*p]
	*p++
	switch c {
	case 'i':
		start := *p
		for *p < len(b) && b[*p] != 'e' {
			*p++
		}
		if *p >= len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		n, err := strconv.ParseInt(string(b[start:*p]), 10, 64)
		*p++
		return n, err
	case 'l':
		var list []any
		for *p < len(b) && b[*p] != 'e' {
			v, err := decode(b, p)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		if *p >= len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		*p++
		return list, nil
	case 'd':
		m := map[string]any{}
		for *p < len(b) && b[*p] != 'e' {
			k, err := decode(b, p)
			if err != nil {
				return nil, err
			}
			key, ok := k.([]byte)
			if !ok {
				return nil, fmt.Errorf("non-string dictionary key")
			}
			v, err := decode(b, p)
			if err != nil {
				return nil, err
			}
			m[string(key)] = v
		}
		if *p >= len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		*p++
		return m, nil
	default:
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("bad bencode prefix")
		}
		start := *p - 1
		for *p < len(b) && b[*p] != ':' {
			*p++
		}
		if *p >= len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		n, err := strconv.Atoi(string(b[start:*p]))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad string length")
		}
		*p++
		if n > len(b)-*p {
			return nil, io.ErrUnexpectedEOF
		}
		v := b[*p : *p+n]
		*p += n
		return v, nil
	}
}

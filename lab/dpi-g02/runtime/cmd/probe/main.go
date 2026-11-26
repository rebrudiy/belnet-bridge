// probe supplies bounded nonce requests and loopback lab control calls.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 2 && os.Args[1] == "clock" {
		return json.NewEncoder(os.Stdout).Encode(clockSnapshot(time.Now()))
	}
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		mux := http.NewServeMux()
		mux.HandleFunc("/proof", func(w http.ResponseWriter, r *http.Request) {
			nonce := r.URL.Query().Get("nonce")
			decoded, decodeErr := hex.DecodeString(nonce)
			size, sizeErr := strconv.Atoi(r.URL.Query().Get("bytes"))
			if decodeErr != nil || len(decoded) != 32 || sizeErr != nil || size < 0 || size > 128*1024 {
				http.Error(w, "invalid proof", http.StatusBadRequest)
				return
			}
			now := time.Now()
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"utc": now.UTC().Format(time.RFC3339Nano), "at_unix_micros": now.UnixMicro(), "nonce": nonce, "bytes": size, "remote": r.RemoteAddr})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"nonce": nonce, "service": "bb-g02-service", "body": strings.Repeat("x", size)})
		})
		server := &http.Server{Addr: ":8082", Handler: mux, ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
		return server.ListenAndServe()
	}
	if len(os.Args) < 2 {
		return fmt.Errorf("use fetch URL BYTES TIMEOUT_MS or admin METHOD URL")
	}
	if os.Args[1] == "admin" {
		if len(os.Args) != 4 {
			return fmt.Errorf("invalid admin arguments")
		}
		body, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, os.Args[2], os.Args[3], strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		if err != nil {
			return err
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("lab HTTP %d: %s", response.StatusCode, data)
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	if os.Args[1] != "fetch" || len(os.Args) != 5 {
		return fmt.Errorf("invalid fetch arguments")
	}
	size, err := strconv.Atoi(os.Args[3])
	if err != nil || size < 0 || size > 128*1024 {
		return fmt.Errorf("invalid body size")
	}
	timeout, err := strconv.Atoi(os.Args[4])
	if err != nil || timeout < 1 || timeout > 20000 {
		return fmt.Errorf("invalid timeout")
	}
	var nonceBytes [32]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	started := time.Now()
	result := map[string]any{"nonce": nonce, "requested_bytes": size, "started": started.UTC().Format(time.RFC3339Nano), "started_unix_micros": started.UnixMicro(), "ok": false}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", "127.3.2.1:53")
	}}
	transport := &http.Transport{DialContext: (&net.Dialer{Resolver: resolver}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(timeout) * time.Millisecond}
	response, err := client.Get(strings.TrimRight(os.Args[2], "/") + "/proof?nonce=" + nonce + "&bytes=" + strconv.Itoa(size))
	if err == nil {
		defer response.Body.Close()
		var proof struct {
			Nonce   string `json:"nonce"`
			Service string `json:"service"`
			Body    string `json:"body"`
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 256<<10)).Decode(&proof)
		result["status"] = response.StatusCode
		result["body_bytes"] = len(proof.Body)
		result["ok"] = err == nil && response.StatusCode == 200 && proof.Nonce == nonce && proof.Service == "bb-g02-service" && len(proof.Body) == size
	}
	if err != nil {
		result["error"] = err.Error()
	}
	finished := time.Now()
	result["finished"] = finished.UTC().Format(time.RFC3339Nano)
	result["finished_unix_micros"] = finished.UnixMicro()
	result["elapsed_ms"] = finished.Sub(started).Milliseconds()
	return json.NewEncoder(os.Stdout).Encode(result)
}

func clockSnapshot(now time.Time) map[string]any {
	return map[string]any{"utc": now.UTC().Format(time.RFC3339Nano), "unix_micros": now.UnixMicro(), "clock": "linux-vm"}
}

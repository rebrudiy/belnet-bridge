package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type connection struct {
	ID        uint64 `json:"id"`
	Hash      string `json:"session_hash"`
	UDP       string `json:"udp_tuple"`
	Connected bool   `json:"connected"`
}
type state struct {
	Connections []connection `json:"connections"`
	Truncated   bool         `json:"metadata_truncated"`
}

func main() {
	if len(os.Args) < 2 {
		panic("use echo|probe")
	}
	if os.Args[1] == "echo" {
		echo()
		return
	}
	if err := probe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func echo() {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12090})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	buf := make([]byte, 65535)
	for {
		n, peer, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"at_unix_micros": time.Now().UnixMicro(), "peer": peer.String(), "bytes": n})
		if _, err := c.WriteToUDP(buf[:n], peer); err != nil {
			return
		}
	}
}
func snapshot(name string) (state, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:2291/state")
	if err != nil {
		return state{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return state{}, err
	}
	if err := os.WriteFile("/work/"+name+".json", raw, 0600); err != nil {
		return state{}, err
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	if response.StatusCode != 200 {
		return s, fmt.Errorf("state status %d", response.StatusCode)
	}
	return s, nil
}
func pairs(s state) map[string]string {
	m := map[string]string{}
	for _, c := range s.Connections {
		if c.Hash != "" && c.UDP != "" {
			m[c.Hash] = c.UDP
		}
	}
	return m
}
func stablePIDs() map[string]string {
	out := map[string]string{}
	for _, file := range []string{"server.pid", "client.pid", "bad.pid"} {
		raw, err := os.ReadFile("/work/" + file)
		if err != nil {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		s, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		tail := strings.Split(strings.TrimSpace(string(s[strings.LastIndex(string(s), ")")+2:])), " ")
		if len(tail) > 19 {
			out[file] = fmt.Sprintf("%d:%s", pid, tail[19])
		}
	}
	return out
}
func startCore() (*exec.Cmd, error) {
	log, err := os.OpenFile("/work/client-core.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/mature/sing-box", "run", "-c", "/work/private/client.json")
	cmd.Stdout = log
	cmd.Stderr = log
	err = cmd.Start()
	_ = log.Close()
	return cmd, err
}
func probe() error {
	result := map[string]any{"fixture_only": true, "native_belnet": false, "started": time.Now().UTC().Format(time.RFC3339Nano)}
	errorsList := []string{}
	recordError := func(err error) {
		if err != nil {
			errorsList = append(errorsList, err.Error())
		}
	}
	attempts := []map[string]any{}
	defer func() {
		result["finished"] = time.Now().UTC().Format(time.RFC3339Nano)
		result["errors"] = errorsList
		result["attempts"] = attempts
		raw, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile("/work/result.json", append(raw, '\n'), 0600)
		_ = json.NewEncoder(os.Stdout).Encode(result)
	}()
	core, err := startCore()
	if err != nil {
		return err
	}
	defer func() {
		if core != nil && core.Process != nil {
			_ = core.Process.Kill()
			_ = core.Wait()
		}
	}()
	time.Sleep(350 * time.Millisecond)
	source, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2091})
	if err != nil {
		return err
	}
	defer source.Close()
	result["primary_udp_source"] = source.LocalAddr().String()
	result["adapter_pids_before"] = stablePIDs()
	result["core_pid_before"] = core.Process.Pid
	exchange := func(c *net.UDPConn, phase string, size int, deadline time.Duration) bool {
		packet := make([]byte, size)
		_, _ = rand.Read(packet)
		fingerprint := hex.EncodeToString(packet[:min(16, len(packet))])
		start := time.Now()
		row := map[string]any{"phase": phase, "bytes": size, "source": c.LocalAddr().String(), "started_unix_micros": start.UnixMicro(), "nonce_prefix": fingerprint, "ok": false}
		_ = c.SetDeadline(start.Add(deadline))
		_, err := c.Write(packet)
		buf := make([]byte, 65535)
		n := 0
		if err == nil {
			n, err = c.Read(buf)
		}
		row["received_bytes"] = n
		row["elapsed_micros"] = time.Since(start).Microseconds()
		if err != nil {
			row["error"] = err.Error()
		} else {
			row["ok"] = bytes.Equal(packet, buf[:n])
			if !bytes.Equal(packet, buf[:n]) {
				row["error"] = "payload mismatch or truncation"
			}
		}
		attempts = append(attempts, row)
		f, e := os.OpenFile("/work/attempts.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e == nil {
			_ = json.NewEncoder(f).Encode(row)
			_ = f.Close()
		}
		return row["ok"].(bool)
	}
	sizes := []int{0, 1, 1200, 60000, 65507}
	beforeOK := true
	for _, n := range sizes {
		if !exchange(source, "before_restart", n, 5*time.Second) {
			beforeOK = false
		}
	}
	before, err := snapshot("server-before-restart")
	recordError(err)
	result["sessions_before"] = pairs(before)
	reset := map[string]any{"signal_at": time.Now().UTC().Format(time.RFC3339Nano), "old_pid": core.Process.Pid}
	_ = core.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- core.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			reset["old_exit_error"] = err.Error()
		}
	case <-time.After(time.Second):
		reset["forced_kill"] = true
		_ = core.Process.Kill()
		<-done
	}
	core = nil
	reset["absent_started"] = time.Now().UTC().Format(time.RFC3339Nano)
	time.Sleep(2 * time.Second)
	core, err = startCore()
	recordError(err)
	reset["restart_started"] = time.Now().UTC().Format(time.RFC3339Nano)
	if core != nil && core.Process != nil {
		reset["new_pid"] = core.Process.Pid
	}
	result["restart"] = reset
	time.Sleep(350 * time.Millisecond)
	afterOK := true
	for _, n := range sizes {
		if !exchange(source, "after_restart", n, 5*time.Second) {
			afterOK = false
		}
	}
	after, err := snapshot("server-after-restart")
	recordError(err)
	result["sessions_after"] = pairs(after)
	result["primary_tuple_sid_preserved"] = len(pairs(before)) == 1 && samePairs(pairs(before), pairs(after))
	second, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2091})
	if err != nil {
		return err
	}
	defer second.Close()
	secondOK := exchange(second, "second_sid", 128, 5*time.Second)
	two, err := snapshot("server-two-sids")
	recordError(err)
	twoPairs := pairs(two)
	tupleSet := map[string]bool{}
	for _, tuple := range twoPairs {
		tupleSet[tuple] = true
	}
	result["second_sid_isolated"] = secondOK && len(twoPairs) == 2 && len(tupleSet) == 2
	bad, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2092})
	if err != nil {
		return err
	}
	defer bad.Close()
	badPassed := exchange(bad, "bad_token", 256, time.Second)
	postBad, err := snapshot("server-after-bad-token")
	recordError(err)
	result["bad_token_no_udp_state"] = !badPassed && samePairs(twoPairs, pairs(postBad))
	result["adapter_pids_after"] = stablePIDs()
	result["adapter_processes_unchanged"] = samePairs(result["adapter_pids_before"].(map[string]string), result["adapter_pids_after"].(map[string]string)) && len(stablePIDs()) == 3
	result["exact_before"] = beforeOK
	result["exact_after"] = afterOK
	result["passed"] = beforeOK && afterOK && result["primary_tuple_sid_preserved"].(bool) && result["second_sid_isolated"].(bool) && result["bad_token_no_udp_state"].(bool) && result["adapter_processes_unchanged"].(bool) && len(errorsList) == 0
	return nil
}
func samePairs(a, b map[string]string) bool {
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

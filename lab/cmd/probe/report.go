package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func report() {
	if len(os.Args) != 3 {
		log.Fatal("report RESULTS-DIRECTORY")
	}
	dir := os.Args[2]
	result := map[string]any{}
	for _, name := range []string{"requests", "steady-requests", "outage-requests", "recovery-requests"} {
		f, err := os.Open(filepath.Join(dir, name+".jsonl"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
		total, ok, malformed := 0, 0, 0
		var elapsed []int64
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				malformed++
				continue
			}
			total++
			if row["ok"] == true {
				ok++
				if n, valid := row["elapsed_ms"].(float64); valid {
					elapsed = append(elapsed, int64(n))
				}
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		f.Close()
		sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
		stats := map[string]any{"requests": total, "succeeded": ok, "failed": total - ok, "malformed_lines": malformed}
		if len(elapsed) > 0 {
			stats["min_ms"] = elapsed[0]
			middle := len(elapsed) / 2
			median := float64(elapsed[middle])
			if len(elapsed)%2 == 0 {
				median = (float64(elapsed[middle-1]) + median) / 2
			}
			stats["median_ms"] = median
			stats["max_ms"] = elapsed[len(elapsed)-1]
		}
		result[name] = stats
	}
	patterns := map[string]*regexp.Regexp{
		"established_session_timeouts": regexp.MustCompile(`session to .* timed out`),
		"pending_session_timeouts":     regexp.MustCompile(`pending session at .* timed out`),
		"path_build_timeouts":          regexp.MustCompile(`path build .* timed out`),
		"path_build_failures":          regexp.MustCompile(`path build .* failed at`),
		"paths_built":                  regexp.MustCompile(`is built, took`),
		"peer_deregister_events":       regexp.MustCompile(`has been de-registered`),
	}
	totals := map[string]int{}
	for _, node := range []string{"seed", "entry1", "entry2", "relay1", "relay2", "relay3", "client", "service"} {
		data, err := os.ReadFile(filepath.Join(dir, node+".log"))
		if err != nil {
			continue
		}
		counts := map[string]int{}
		for name, pattern := range patterns {
			counts[name] = len(pattern.FindAll(data, -1))
			totals[name] += counts[name]
		}
		result[node+"_events"] = counts
	}
	result["all_nodes_events"] = totals
	result["event_scope"] = "complete saved node logs, including startup and teardown"
	if file, err := os.Open(filepath.Join(dir, "censor.log")); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) == nil && row["event"] == "summary" {
				result["censor_summary"] = row
				result["measurement_end_derived_from_censor_summary"] = row["time"]
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
	manifest, _ := os.ReadFile(filepath.Join(dir, "manifest.txt"))
	result["manifest"] = strings.Split(strings.TrimSpace(string(manifest)), "\n")
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
}

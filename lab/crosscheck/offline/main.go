// Command offline scores archived packet-derived prefixes with a frozen model.
// It never fits a model, recalibrates a threshold, or alters evidence.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"os"
	"path/filepath"
)

type flow struct {
	SessionID        string   `json:"session_id"`
	Eligible         bool     `json:"eligible"`
	ExclusionReasons []string `json:"exclusion_reasons"`
}
type capture struct {
	PCAP         string                `json:"pcap"`
	SHA          string                `json:"pcap_sha256"`
	Flows        []flow                `json:"flows"`
	Observations []traffic.Observation `json:"observations"`
}
type input struct {
	PCAPs []capture `json:"pcaps"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if len(os.Args) != 4 {
		panic("usage: offline MODEL_JSON REASSEMBLED_JSON OUTPUT_JSON")
	}
	data, err := os.ReadFile(os.Args[1])
	must(err)
	sum := sha256.Sum256(data)
	f, err := os.Open(os.Args[1])
	must(err)
	defer f.Close()
	model, err := traffic.Load(f)
	must(err)
	raw, err := os.ReadFile(os.Args[2])
	must(err)
	var in input
	must(json.Unmarshal(raw, &in))
	var results []map[string]any
	eligibleTotal, detectedTotal := 0, 0
	for _, c := range in.PCAPs {
		meta := map[string]flow{}
		for _, v := range c.Flows {
			meta[v.SessionID] = v
		}
		rows := []map[string]any{}
		eligible, detected := 0, 0
		for _, o := range c.Observations {
			m := meta[o.SessionID]
			score := model.Score(o)
			block := model.Block(o)
			rows = append(rows, map[string]any{"session_id": o.SessionID, "eligible": m.Eligible, "exclusion_reasons": m.ExclusionReasons, "records": len(o.Events), "score": score, "threshold": model.Threshold, "positive_verdict": block})
			if m.Eligible && filepath.Base(c.PCAP) == "C-onlytls.pcap" {
				eligible++
				if block {
					detected++
				}
			}
		}
		eligibleTotal += eligible
		detectedTotal += detected
		results = append(results, map[string]any{"pcap": c.PCAP, "sha256": c.SHA, "scores": rows, "eligible_labelled_C_flows": eligible, "detected_eligible_C_flows": detected})
	}
	output := map[string]any{"frozen_model": os.Args[1], "model_sha256": hex.EncodeToString(sum[:]), "threshold": model.Threshold, "classifier_changed": false, "training_or_recalibration_performed": false, "timestamp_source": "PCAP arrival/completion, unlike training raw-socket callback; exploratory cross-domain replay only", "eligible_labelled_C_flows": eligibleTotal, "detected_eligible_C_flows": detectedTotal, "benign_test_groups": 0, "false_positive_rate": "not measured", "captures": results}
	out, err := json.MarshalIndent(output, "", "  ")
	must(err)
	must(os.WriteFile(os.Args[3], append(out, '\n'), 0600))
	fmt.Printf("Frozen forest on archived Claude C: %d/%d eligible flows flagged (PCAP timestamps, exploratory)\n", detectedTotal, eligibleTotal)
}

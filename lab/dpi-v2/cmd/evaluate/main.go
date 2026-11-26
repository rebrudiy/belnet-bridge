// evaluate is the auxiliary forest check. Classical signatures remain a
// separate explicit attacker. Test observations never enter Fit/calibration.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rebrudiy/belnet-bridge/internal/traffic"
)

func read(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
func save(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func main() {
	dataPath := flag.String("data", "out/dpi-v2/dataset.json", "observations")
	out := flag.String("out", "out/dpi-v2/forest", "new output directory")
	flag.Parse()
	if err := run(*dataPath, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, out string) error {
	if _, err := os.Stat(filepath.Join(out, "report.json")); err == nil {
		return fmt.Errorf("refusing to overwrite model evaluation")
	}
	var observations []traffic.Observation
	if err := read(path, &observations); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	var old traffic.Model
	if err := read("lab/evolution/results/full-15-queuefix-20261119/final-attacker.json", &old); err != nil {
		return err
	}
	train, calibration := []traffic.Observation{}, []traffic.Observation{}
	for _, o := range observations {
		if o.Split == traffic.SplitTrain {
			train = append(train, o)
		}
		if o.Class == traffic.ClassBenign && o.Split == traffic.SplitValidation {
			calibration = append(calibration, o)
		}
	}
	adaptive, err := traffic.Fit(traffic.TrainingConfig{Seed: 2026111907, Trees: 128, Depth: 8, FPRBudget: .05}, train, calibration)
	if err != nil {
		return err
	}
	if err := save(filepath.Join(out, "adaptive-model.json"), adaptive); err != nil {
		return err
	}
	report := map[string]any{"role": "auxiliary forest, not classical DPI", "old": evaluate(&old, observations), "adaptive": evaluate(adaptive, observations), "calibration": adaptive.BenignValidation, "threshold": adaptive.Threshold, "train_positive": adaptive.TrainingBelNet, "train_benign": adaptive.TrainingBenign, "training_groups": adaptive.TrainingGroups}
	if err := save(filepath.Join(out, "report.json"), report); err != nil {
		return err
	}
	fmt.Printf("adaptive threshold %.8f; train %d+ / %d-; calibration FP %d/%d\n", adaptive.Threshold, adaptive.TrainingBelNet, adaptive.TrainingBenign, adaptive.BenignValidation.FalsePositive, adaptive.BenignValidation.Negative)
	return nil
}

func evaluate(model *traffic.Model, observations []traffic.Observation) map[string]any {
	buckets := map[string][]traffic.Observation{}
	groups := map[string]bool{}
	for _, o := range observations {
		buckets["split/"+o.Split] = append(buckets["split/"+o.Split], o)
		buckets[o.Split+"/profile/"+o.Profile] = append(buckets[o.Split+"/profile/"+o.Profile], o)
		domain := "native"
		if strings.HasPrefix(o.Profile, "local-") {
			domain = "local-synthetic"
		}
		if strings.HasPrefix(o.Profile, "real-") {
			domain = "real-browser"
		}
		buckets[o.Split+"/domain/"+domain] = append(buckets[o.Split+"/domain/"+domain], o)
		if model.Block(o) {
			groups[o.GroupID] = true
		}
	}
	metrics := map[string]traffic.Metrics{}
	for key, rows := range buckets {
		metrics[key] = traffic.Evaluate(model, rows)
	}
	groupBuckets := map[string]map[string]bool{}
	for _, o := range observations {
		key := o.Split + "/" + o.Class
		if groupBuckets[key] == nil {
			groupBuckets[key] = map[string]bool{}
		}
		groupBuckets[key][o.GroupID] = groups[o.GroupID]
	}
	groupMetrics := map[string]any{}
	for key, rows := range groupBuckets {
		hits := 0
		for _, hit := range rows {
			if hit {
				hits++
			}
		}
		groupMetrics[key] = map[string]int{"any_blocked_groups": hits, "groups": len(rows)}
	}
	return map[string]any{"flow_metrics": metrics, "group_any_block": groupMetrics}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"math"
	"sort"
)

func evidence(w Window) (bool, []string) {
	reasons := []string{}
	if !w.Eligible {
		reasons = append(reasons, "coverage_ineligible")
	}
	if w.OrderingAmbiguous {
		reasons = append(reasons, "ambiguous_order_ML_vector_abstains")
	}
	if len(w.Events) < MinimumRecords {
		reasons = append(reasons, "need16_canonical_records")
	}
	return len(reasons) == 0, reasons
}
func observation(g Group, w Window) traffic.Observation {
	events := make([]traffic.Event, 0, len(w.Events))
	for _, e := range w.Events {
		events = append(events, traffic.Event{AtMicros: e.At, Direction: e.Direction, Bytes: e.Bytes})
	}
	return traffic.Observation{SessionID: g.Metadata.GroupID + "/" + w.ID, GroupID: g.Metadata.GroupID, Split: g.Metadata.Split, Class: g.Metadata.Class, Profile: g.Metadata.Profile, Events: events}
}
func validateInput(groups []Group) error {
	seen := map[string]string{}
	for _, g := range groups {
		if (g.Metadata.Split != "train" && g.Metadata.Split != "validation") || g.Metadata.Scope != "primary" {
			return fmt.Errorf("test/diagnostic/development cannot enter auxiliary calibration")
		}
		if len(g.PrimaryFlows) == 0 {
			return fmt.Errorf("nonempty actual primary flow inventory required")
		}
		if !g.Complete {
			return fmt.Errorf("incomplete calibration group%s: %v", g.Metadata.GroupID, g.Reasons)
		}
		if split, ok := seen[g.Metadata.SourceWorkloadID]; ok && split != g.Metadata.Split {
			return fmt.Errorf("paired source split leak")
		}
		seen[g.Metadata.SourceWorkloadID] = g.Metadata.Split
	}
	return nil
}
func fitAuxiliary(groups []Group, f Freeze, freezeSHA string) (Policy, error) {
	if err := validateInput(groups); err != nil {
		return Policy{}, err
	}
	p := Policy{CoverageSHA: CoverageSHA, Schema: 1, Role: Role, Version: Version, FreezeSHA: freezeSHA, FeaturesSHA: definitionsSHA(), LibrarySHA: LibrarySourceSHA, OrderingSHA: OrderingSHA, Config: FixedConfig, Calibration: map[string]Metrics{}, LastDevelopmentCapture: latestCapture(groups), Limits: []string{"AUXILIARY only; primary remains classical23.", "80 fixed ciphertextmetadata features, max64records/2s, predeclared single canonicalview; no ordinal featurefork.", "All ambiguous windows abstain; incomplete/sparse/disabled outcomes are never stealth.", "Own separate group+directflow empirical5% budget; OR with classic does NOT inherit5%.", "Metadata group/class/profile/source/stack IDs are provenance, excluded from model feature vector.", "Capture-time sensor-conditioned features, not physical request/reply causality or ISP guarantee."}}
	raw, _ := json.Marshal(groups)
	p.CalibrationSHA = sha(raw)
	train, val := []traffic.Observation{}, []traffic.Observation{}
	positiveGroups, negativeGroups := map[string]bool{}, map[string]bool{}
	for _, g := range groups {
		for _, w := range g.Windows {
			ok, _ := evidence(w)
			if !ok {
				continue
			}
			o := observation(g, w)
			if g.Metadata.Split == "train" {
				train = append(train, o)
				if g.Metadata.Class == "benign" {
					negativeGroups[g.Metadata.GroupID] = true
				} else {
					positiveGroups[g.Metadata.GroupID] = true
				}
			} else if g.Metadata.Split == "validation" && g.Metadata.Class == "benign" {
				val = append(val, o)
			}
		}
	}
	p.TrainingGroups = len(positiveGroups) + len(negativeGroups)
	p.TrainingWindows = len(train)
	p.ValidationWindows = len(val)
	if len(positiveGroups) < 2 || len(negativeGroups) < 2 || len(val) == 0 {
		p.Disabled = true
		p.DisabledReason = "insufficient_eligible_train_groups_or_benign_validation"
	} else {
		model, err := traffic.Fit(FixedConfig, train, val)
		if err != nil {
			return Policy{}, err
		}
		p.Model = model
		threshold, err := jointThreshold(groups, model)
		if err != nil {
			return Policy{}, err
		}
		p.Threshold = threshold
		p.Model.Threshold = threshold
		p.Model.BenignValidation = traffic.Evaluate(p.Model, val)
		if threshold >= maximumScoreBound(model) {
			p.Disabled = true
			p.DisabledReason = "joint_FP_budget_disables_classifier"
		}
	}
	for _, split := range []string{"train", "validation"} {
		subset := []Group{}
		for _, g := range groups {
			if g.Metadata.Split == split {
				subset = append(subset, g)
			}
		}
		m := measure(evaluate(subset, p))
		if m.Benign == 0 || m.BenignFlows == 0 {
			return Policy{}, fmt.Errorf("benign%s groups/actualflows required", split)
		}
		if m.GroupFPR == nil || *m.GroupFPR > .05 || m.FlowFPR == nil || *m.FlowFPR > .05 {
			return Policy{}, fmt.Errorf("auxiliary joint group/directflow calibration failed")
		}
		p.Calibration[split] = m
	}
	return p, nil
}
func strictCutoff(scores []float64) float64 {
	sort.Sort(sort.Reverse(sort.Float64Slice(scores)))
	allowed := int(math.Floor(.05*float64(len(scores)) + 1e-12))
	return scores[allowed]
}
func jointThreshold(groups []Group, m *traffic.Model) (float64, error) {
	threshold := 0.0
	for _, split := range []string{"train", "validation"} {
		groupScores, flowScores := []float64{}, []float64{}
		for _, g := range groups {
			if g.Metadata.Class != "benign" || g.Metadata.Split != split {
				continue
			}
			best := 0.0
			flows := map[string]float64{}
			for id, primary := range g.PrimaryFlows {
				if primary {
					flows[id] = 0
				}
			}
			for _, w := range g.Windows {
				if _, ok := flows[w.FlowID]; !ok {
					return 0, fmt.Errorf("window not in actual primary flow inventory")
				}
				if ok, _ := evidence(w); ok {
					score := m.Score(observation(g, w))
					if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
						return 0, fmt.Errorf("invalid forest score")
					}
					best = math.Max(best, score)
					flows[w.FlowID] = math.Max(flows[w.FlowID], score)
				}
			}
			groupScores = append(groupScores, best)
			for _, s := range flows {
				flowScores = append(flowScores, s)
			}
		}
		if len(groupScores) == 0 || len(flowScores) == 0 {
			return 0, fmt.Errorf("benign%s groups/flows missing", split)
		}
		threshold = math.Max(threshold, strictCutoff(groupScores))
		threshold = math.Max(threshold, strictCutoff(flowScores))
	}
	return threshold, nil
}
func maximumScoreBound(m *traffic.Model) float64 {
	if m == nil || len(m.Trees) == 0 {
		return 0
	}
	upper := 0.0
	for _, tree := range m.Trees {
		best := 0.0
		for _, n := range tree.Nodes {
			if n.Leaf {
				best = math.Max(best, n.Probability)
			}
		}
		upper += best
	}
	return upper / float64(len(m.Trees))
}
func validatePolicy(p Policy) error {
	if p.FrozenAt.IsZero() || p.LastDevelopmentCapture.IsZero() || !p.FrozenAt.After(p.LastDevelopmentCapture) || p.Schema != 1 || p.Role != Role || p.Version != Version || p.FeaturesSHA != definitionsSHA() || p.LibrarySHA != LibrarySourceSHA || p.CoverageSHA != CoverageSHA || p.OrderingSHA != OrderingSHA || p.Config != FixedConfig || !hexSHA(p.CalibrationSHA) || math.IsNaN(p.Threshold) || math.IsInf(p.Threshold, 0) || p.Threshold < 0 || p.Threshold > 1 {
		return fmt.Errorf("invalid auxiliary policy contract")
	}
	if p.Model == nil {
		if !p.Disabled || p.DisabledReason == "" {
			return fmt.Errorf("missing model without explicitdisabled state")
		}
		return nil
	}
	raw, err := json.Marshal(p.Model)
	if err != nil {
		return err
	}
	loaded, err := traffic.Load(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if loaded.Config != FixedConfig || loaded.Threshold != p.Threshold || len(loaded.Trees) != FixedConfig.Trees {
		return fmt.Errorf("forest config/threshold mismatch")
	}
	for _, tree := range loaded.Trees {
		var depth func(int, int) bool
		depth = func(i, d int) bool {
			if d > FixedConfig.Depth {
				return false
			}
			if tree.Nodes[i].Leaf {
				return true
			}
			return depth(tree.Nodes[i].Left, d+1) && depth(tree.Nodes[i].Right, d+1)
		}
		if !depth(0, 0) {
			return fmt.Errorf("model exceeds predeclared depth")
		}
	}
	if (p.Threshold >= maximumScoreBound(loaded)) != p.Disabled {
		return fmt.Errorf("classifier disabled status mismatch")
	}
	return nil
}

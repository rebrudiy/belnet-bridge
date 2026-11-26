// Command defender jointly calibrates one session OR over all PCAP windows/rules.
// The existing deterministic classical CLI supplies scores; no formula is copied.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

const DefenderVersion = "g03-defender-v1"

type Assignment struct {
	SourceWorkloadID string `json:"source_workload_id"`
	Scope            string `json:"scope"`
	Transport        string `json:"transport"`
	ClientStack      string `json:"client_stack"`
	GroupID          string `json:"group_id"`
	Split            string `json:"split"`
	Class            string `json:"class"`
	Profile          string `json:"profile"`
}
type Freeze struct {
	CollectorSHA    string       `json:"collector_freeze_sha256"`
	DevelopmentSHA  string       `json:"development_freeze_sha256,omitempty"`
	PolicySHA       string       `json:"policy_sha256,omitempty"`
	ObserverSHA     string       `json:"observer_sha256"`
	ObserverVersion string       `json:"observer_version"`
	PrefixGrace     int          `json:"prefix_grace_seconds"`
	Schema          int          `json:"schema"`
	Stage           string       `json:"stage"`
	Viability       string       `json:"stage_a_viability"`
	Frozen          time.Time    `json:"frozen_at"`
	MeasuredSeconds int          `json:"measured_seconds"`
	CaptureSeconds  int          `json:"capture_seconds"`
	WindowOffsets   []int        `json:"window_offsets_seconds"`
	WindowSeconds   int          `json:"window_seconds"`
	Cooldown        int          `json:"cooldown_seconds"`
	CaptureCap      int64        `json:"capture_cap_bytes"`
	DefinitionsSHA  string       `json:"definitions_sha256"`
	EngineSHA       string       `json:"score_engine_sha256"`
	Groups          []Assignment `json:"groups"`
	Budget          float64      `json:"group_fpr_budget"`
	FlowBudget      float64      `json:"direct_flow_fpr_budget"`
}
type Metadata struct {
	MeasurementStartMicros int64 `json:"measurement_start_unix_micros"`
	PrefixGrace            int   `json:"prefix_grace_seconds"`
	WindowOffsets          []int `json:"window_offsets_seconds"`
	Assignment
	CaptureStarted  time.Time `json:"capture_started_utc"`
	CaptureEnded    time.Time `json:"capture_ended_utc"`
	FreezeSHA       string    `json:"freeze_sha256"`
	CaptureCap      int64     `json:"capture_cap_bytes"`
	MeasuredSeconds int       `json:"measured_seconds"`
}
type Event struct {
	At        int64 `json:"at_micros"`
	Direction int   `json:"direction"`
	Bytes     int   `json:"bytes"`
}
type Window struct {
	Primary  bool               `json:"primary"`
	Reasons  []string           `json:"coverage_reasons"`
	ID       string             `json:"session_id"`
	GroupID  string             `json:"group_id"`
	Split    string             `json:"split"`
	Class    string             `json:"class"`
	Profile  string             `json:"profile"`
	FlowID   string             `json:"flow_id"`
	Kind     string             `json:"window_kind"`
	Start    time.Time          `json:"window_start_utc"`
	End      time.Time          `json:"window_end_utc"`
	Eligible bool               `json:"eligible"`
	Status   string             `json:"status"`
	Events   []Event            `json:"events"`
	Scores   map[string]float64 `json:"scores,omitempty"`
}
type Capture struct {
	Version          string        `json:"version"`
	MeasurementStart *time.Time    `json:"measurement_start_utc"`
	MeasurementEnd   *time.Time    `json:"measurement_end_utc"`
	Flows            []FlowSummary `json:"flows"`
	Schema           int           `json:"schema"`
	Metadata         Metadata      `json:"metadata"`
	Coverage         bool          `json:"coverage_complete"`
	GroupWindows     []Window      `json:"group_windows"`
	Windows          []Window      `json:"windows"`
	GlobalReasons    []string      `json:"global_coverage_reasons"`
	PCAPSHA          string        `json:"pcap_sha256"`
	Anchor           *time.Time    `json:"group_first_tls23_utc"`
}
type FlowSummary struct {
	ID    string     `json:"flow_id"`
	First *time.Time `json:"first_tls23_utc"`
}
type Group struct {
	Diagnostics []Window `json:"diagnostic_windows"`
	Metadata    Metadata `json:"metadata"`
	Complete    bool     `json:"coverage_complete"`
	Reasons     []string `json:"coverage_reasons"`
	Windows     []Window `json:"windows"`
	SourceSHA   string   `json:"source_sha256"`
}
type Rule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Response   string `json:"transport_hypothesis"`
}
type Catalog struct {
	SHA   string `json:"definitions_sha256"`
	Rules []Rule `json:"rules"`
}
type RulePolicy struct {
	Rule      Rule    `json:"rule"`
	Threshold float64 `json:"threshold"`
	Enabled   bool    `json:"enabled"`
}
type Calibration struct {
	CompleteBenign             int      `json:"complete_benign_groups"`
	IncompleteBenign           int      `json:"incomplete_benign_groups"`
	CompletePositive           int      `json:"complete_positive_groups"`
	IncompletePositive         int      `json:"incomplete_positive_groups"`
	CompleteFPR                *float64 `json:"complete_group_fpr"`
	CompleteFP                 int      `json:"complete_false_positive_groups"`
	CoverageEligibleWindows    int      `json:"coverage_eligible_windows"`
	RuleEligibleWindows        int      `json:"rule_eligible_windows"`
	EnabledRuleEligibleWindows int      `json:"enabled_rule_eligible_windows"`
	Groups                     int      `json:"groups"`
	Benign                     int      `json:"benign_groups"`
	FP                         int      `json:"false_positive_groups"`
	FPR                        *float64 `json:"group_fpr"`
	Positive                   int      `json:"positive_groups"`
	TP                         int      `json:"detected_positive_groups"`
	TPR                        *float64 `json:"group_tpr"`
	Complete                   int      `json:"complete_groups"`
	Incomplete                 int      `json:"incomplete_groups"`
	RuleEligibleBenign         int      `json:"rule_eligible_benign_groups"`
	EligibleFPR                *float64 `json:"eligible_group_fpr"`
	Abstain                    int      `json:"complete_abstaining_groups"`
	Windows                    int      `json:"windows"`
	WindowFP                   int      `json:"direct_rule_hit_false_positive_windows"`
	BenignWindows              int      `json:"benign_windows"`
	Flows                      int      `json:"flows"`
	FPFlows                    int      `json:"direct_rule_hit_false_positive_flows"`
	BenignFlows                int      `json:"benign_flows"`
	FlowFPR                    *float64 `json:"direct_rule_hit_flow_fpr"`
}
type Policy struct {
	EffectiveRules         int                    `json:"effective_rules"`
	Version                string                 `json:"version"`
	MeasuredSeconds        int                    `json:"measured_seconds"`
	PrefixGrace            int                    `json:"prefix_grace_seconds"`
	EnabledRules           int                    `json:"enabled_rules"`
	LastDevelopmentCapture time.Time              `json:"last_development_capture_ended_utc"`
	Schema                 int                    `json:"schema"`
	Method                 string                 `json:"method"`
	FreezeSHA              string                 `json:"freeze_sha256"`
	DefinitionsSHA         string                 `json:"definitions_sha256"`
	EngineSHA              string                 `json:"score_engine_sha256"`
	CalibrationSHA         string                 `json:"calibration_sha256"`
	Budget                 float64                `json:"group_fpr_budget"`
	FlowBudget             float64                `json:"direct_flow_fpr_budget"`
	Margin                 float64                `json:"joint_group_margin"`
	Rules                  []RulePolicy           `json:"rules"`
	Windows                []int                  `json:"window_offsets_seconds"`
	WindowSeconds          int                    `json:"window_seconds"`
	Cooldown               int                    `json:"cooldown_seconds"`
	Calibration            map[string]Calibration `json:"calibration"`
	Limits                 []string               `json:"limits"`
	FrozenAt               time.Time              `json:"policy_frozen_at"`
}
type WindowDecision struct {
	Kind                string             `json:"window_kind"`
	EnabledRuleEligible bool               `json:"enabled_rule_eligible"`
	ID                  string             `json:"session_id"`
	FlowID              string             `json:"flow_id"`
	Start               time.Time          `json:"window_start_utc"`
	End                 time.Time          `json:"window_end_utc"`
	Eligible            bool               `json:"coverage_eligible"`
	RuleEligible        bool               `json:"rule_eligible"`
	Hits                []string           `json:"hits"`
	Scores              map[string]float64 `json:"scores"`
}
type Decision struct {
	SourceWorkloadID    string           `json:"source_workload_id"`
	ClientStack         string           `json:"client_stack"`
	Scope               string           `json:"scope"`
	Transport           string           `json:"transport"`
	EnabledRuleEligible bool             `json:"enabled_rule_eligible"`
	ClassifierEmpty     bool             `json:"classifier_empty_or_disabled"`
	Abstained           bool             `json:"abstained"`
	GroupID             string           `json:"group_id"`
	Split               string           `json:"split"`
	Class               string           `json:"class"`
	Profile             string           `json:"profile"`
	Complete            bool             `json:"coverage_complete"`
	Detected            bool             `json:"any_detected"`
	RuleEligible        bool             `json:"rule_eligible"`
	Status              string           `json:"status"`
	Reasons             []string         `json:"coverage_reasons"`
	Windows             []WindowDecision `json:"windows"`
}
type ReportRef struct {
	CoverageErrors []string `json:"coverage_errors,omitempty"`
	GroupID        string   `json:"group_id"`
	Split          string   `json:"split"`
	Path           string   `json:"path"`
}
type Index struct {
	CoverageErrors []string    `json:"coverage_errors,omitempty"`
	Schema         int         `json:"schema"`
	Stage          string      `json:"stage"`
	Reports        []ReportRef `json:"reports"`
}

func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	v := float64(n) / float64(d)
	return &v
}
func sha(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func read(path string, target any) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err = json.Unmarshal(raw, target); err != nil {
		return "", err
	}
	return sha(raw), nil
}
func write(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}
func cutoff(values []float64, budget float64) float64 {
	if len(values) == 0 {
		return 2
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(values)))
	allowed := int(math.Floor(budget*float64(len(values)) + 1e-12))
	return math.Nextafter(values[allowed], math.Inf(1))
}
func command(engine string, args ...string) error {
	cmd := exec.Command(engine, args...)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("classical score engine: %w: %s", err, raw)
	}
	return nil
}
func catalog(engine, work string) (Catalog, error) {
	raw, err := os.ReadFile(engine)
	if err != nil {
		return Catalog{}, err
	}
	_ = raw
	path := filepath.Join(work, "catalog.json")
	if err = command(engine, "catalog", "-output", path); err != nil {
		return Catalog{}, err
	}
	var c Catalog
	_, err = read(path, &c)
	if len(c.Rules) != 15 && err == nil {
		err = fmt.Errorf("exact15-rule catalog required")
	}
	return c, err
}
func scoreGroups(groups []Group, engine, work string, c Catalog) error {
	rules := []RulePolicy{}
	rounds := []map[string]any{}
	for i, r := range c.Rules {
		rules = append(rules, RulePolicy{r, 2, false})
		rounds = append(rounds, map[string]any{"number": i + 1, "added_rule": r.ID, "joint_margin": 0, "rules": append([]RulePolicy(nil), rules...), "calibration": map[string]any{}})
	}
	scorePolicy := filepath.Join(work, "score-only.json")
	if err := write(scorePolicy, map[string]any{"schema": 1, "definitions_sha256": c.SHA, "calibration_sha256": "score-only-no-fitting", "fpr_budget": 0.05, "individual_rules": rules, "rounds": rounds}); err != nil {
		return err
	}
	for i := range groups {
		g := &groups[i]
		observations := []Window{}
		for _, w := range g.Windows {
			if w.Eligible {
				observations = append(observations, w)
			}
		}
		if len(observations) == 0 {
			continue
		}
		input, output := filepath.Join(work, fmt.Sprintf("group-%04d-input.json", i)), filepath.Join(work, fmt.Sprintf("group-%04d-scores.json", i))
		if err := write(input, observations); err != nil {
			return err
		}
		if err := command(engine, "evaluate", "-policy", scorePolicy, "-input", input, "-split", "all", "-output", output); err != nil {
			return err
		}
		var scored struct {
			DefinitionsSHA string `json:"definitions_sha256"`
			Decisions      []struct {
				ID     string             `json:"session_id"`
				Round  int                `json:"round"`
				Scores map[string]float64 `json:"scores"`
			} `json:"decisions"`
		}
		if _, err := read(output, &scored); err != nil {
			return err
		}
		if scored.DefinitionsSHA != c.SHA {
			return fmt.Errorf("score definition mismatch")
		}
		byID := map[string]map[string]float64{}
		for _, d := range scored.Decisions {
			if d.Round == 15 {
				byID[d.ID] = d.Scores
			}
		}
		for j := range g.Windows {
			w := &g.Windows[j]
			if w.Eligible {
				scores, ok := byID[w.ID]
				if !ok {
					return fmt.Errorf("missing score window")
				}
				for _, s := range scores {
					if math.IsNaN(s) || math.IsInf(s, 0) || s < 0 || s > 1 {
						return fmt.Errorf("invalid score")
					}
				}
				w.Scores = scores
			}
		}
	}
	return nil
}
func groupRuleMax(g Group, id string) float64 {
	best := -1.0
	for _, w := range g.Windows {
		if w.Eligible {
			if s, ok := w.Scores[id]; ok {
				best = math.Max(best, s)
			}
		}
	}
	return best
}
func groupMargin(g Group, rules []RulePolicy) float64 {
	best := -2.0
	for _, r := range rules {
		if r.Enabled {
			score := groupRuleMax(g, r.Rule.ID)
			if score >= 0 {
				best = math.Max(best, score-r.Threshold)
			}
		}
	}
	return best
}
func flowValues(g Group, scorer func(Window) float64) []float64 {
	byFlow := map[string]float64{}
	for _, w := range g.Windows {
		if _, ok := byFlow[w.FlowID]; !ok {
			byFlow[w.FlowID] = -2
		}
		if w.Eligible {
			byFlow[w.FlowID] = math.Max(byFlow[w.FlowID], scorer(w))
		}
	}
	ids := make([]string, 0, len(byFlow))
	for id := range byFlow {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]float64, 0, len(ids))
	for _, id := range ids {
		out = append(out, byFlow[id])
	}
	return out
}
func windowMargin(w Window, rules []RulePolicy) float64 {
	best := -2.0
	for _, r := range rules {
		if r.Enabled {
			if score, ok := w.Scores[r.Rule.ID]; ok {
				best = math.Max(best, score-r.Threshold)
			}
		}
	}
	return best
}
func calibrate(groups []Group, c Catalog, f Freeze, freezeSHA string, budget float64) (Policy, error) {
	if budget < 0 || budget >= 1 {
		return Policy{}, fmt.Errorf("budget must be[0,1)")
	}
	for _, g := range groups {
		if g.Metadata.Scope != "primary" || (g.Metadata.Class == "benign" && g.Metadata.Transport != "ordinary-tls") {
			return Policy{}, fmt.Errorf("nonprimary/REALITY benign cannot enter primary calibration")
		}
		if g.Metadata.Split == "test" {
			return Policy{}, fmt.Errorf("test groups cannot enter calibration")
		}
		if !g.Complete {
			return Policy{}, fmt.Errorf("incomplete group %s: %v; no silent eligibility filtering", g.Metadata.GroupID, g.Reasons)
		}
	}
	p := Policy{Version: DefenderVersion, Schema: 3, MeasuredSeconds: f.MeasuredSeconds, PrefixGrace: f.PrefixGrace, Method: "session/flow OR MAX across all declared windows,15rules and reconnects", FreezeSHA: freezeSHA, DefinitionsSHA: c.SHA, EngineSHA: f.EngineSHA, Budget: budget, FlowBudget: budget, Windows: f.WindowOffsets, WindowSeconds: f.WindowSeconds, Cooldown: f.Cooldown, Calibration: map[string]Calibration{}, Limits: []string{"Tooling score policy, not a claim of native functional viability", "All windows/reconnects of a group remain in the same split", "Complete sparse windows abstain; censored groups do not become passes", "Both empirical session-OR and direct-rule-hit flow FPR budgets are calibrated jointly", "Direct-rule-hit flow counts exclude collateral blocking from an IP/endpoint cooldown", "30-second persistence is declared policy; live enforcement must be separately measured", "Positive labels denote supplied group class; native payload/nonce eligibility requires external metadata join"}}
	raw, _ := json.Marshal(groups)
	p.CalibrationSHA = sha(raw)
	for _, r := range c.Rules {
		threshold := 0.0
		for _, split := range []string{"train", "validation"} {
			scores := []float64{}
			flowScores := []float64{}
			for _, g := range groups {
				if g.Metadata.Split == split && g.Metadata.Class == "benign" {
					scores = append(scores, groupRuleMax(g, r.ID))
					flowScores = append(flowScores, flowValues(g, func(w Window) float64 {
						if s, ok := w.Scores[r.ID]; ok {
							return s
						}
						return -1
					})...)
				}
			}
			if len(scores) == 0 || len(flowScores) == 0 {
				return Policy{}, fmt.Errorf("benign%s groups required", split)
			}
			threshold = math.Max(threshold, cutoff(scores, budget))
			threshold = math.Max(threshold, cutoff(flowScores, budget))
		}
		p.Rules = append(p.Rules, RulePolicy{r, threshold, threshold <= 1})
		if threshold <= 1 {
			p.EnabledRules++
		}
	}
	for _, split := range []string{"train", "validation"} {
		scores := []float64{}
		flowScores := []float64{}
		for _, g := range groups {
			if g.Metadata.Split == split && g.Metadata.Class == "benign" {
				scores = append(scores, groupMargin(g, p.Rules))
				flowScores = append(flowScores, flowValues(g, func(w Window) float64 { return windowMargin(w, p.Rules) })...)
			}
		}
		p.Margin = math.Max(p.Margin, cutoff(scores, budget))
		p.Margin = math.Max(p.Margin, cutoff(flowScores, budget))
	}
	for _, r := range p.Rules {
		if effective(r, p.Margin) {
			p.EffectiveRules++
		}
	}
	decisions := evaluate(groups, p)
	for _, split := range []string{"train", "validation"} {
		subset := []Decision{}
		for _, d := range decisions {
			if d.Split == split {
				subset = append(subset, d)
			}
		}
		m := measure(subset)
		if m.FPR == nil || *m.FPR > budget || m.FlowFPR == nil || *m.FlowFPR > budget {
			return Policy{}, fmt.Errorf("joint group/direct-flow calibration failed")
		}
		p.Calibration[split] = m
	}
	return p, nil
}
func validatePolicy(p Policy, c Catalog, f Freeze) error {
	if p.Schema != 3 || p.Version != DefenderVersion || p.MeasuredSeconds != f.MeasuredSeconds || p.PrefixGrace != f.PrefixGrace || p.FrozenAt.IsZero() || p.Budget != f.Budget || p.FlowBudget != f.FlowBudget || p.Cooldown != f.Cooldown || p.WindowSeconds != f.WindowSeconds || len(p.Rules) != len(c.Rules) || len(p.Windows) != len(f.WindowOffsets) || math.IsNaN(p.Margin) || math.IsInf(p.Margin, 0) || p.Margin < 0 {
		return fmt.Errorf("invalid frozen session policy")
	}
	enabled := 0
	for i, r := range p.Rules {
		if r.Enabled {
			enabled++
		}
		if r.Rule != c.Rules[i] || r.Threshold < 0 || math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Enabled != (r.Threshold <= 1) {
			return fmt.Errorf("invalid frozen rule %d", i+1)
		}
	}
	active := 0
	for _, r := range p.Rules {
		if effective(r, p.Margin) {
			active++
		}
	}
	if active != p.EffectiveRules {
		return fmt.Errorf("effective rule count mismatch")
	}
	if enabled != p.EnabledRules {
		return fmt.Errorf("enabled rule count mismatch")
	}
	for i, offset := range p.Windows {
		if offset != f.WindowOffsets[i] {
			return fmt.Errorf("policy window schedule mismatch")
		}
	}
	return nil
}
func validateTestChronology(groups []Group, p Policy) error {
	for _, g := range groups {
		if g.Metadata.Split == "test" && g.Metadata.CaptureStarted.IsZero() && !g.Complete {
			continue
		}
		if g.Metadata.Split == "test" && !g.Metadata.CaptureStarted.After(p.FrozenAt) {
			return fmt.Errorf("sealed test capture must start after DPI policy freeze; previous captures are development only")
		}
	}
	return nil
}
func effective(r RulePolicy, margin float64) bool { return r.Enabled && 1-r.Threshold >= margin }

func evaluate(groups []Group, p Policy) []Decision {
	out := []Decision{}
	for _, g := range groups {
		d := Decision{GroupID: g.Metadata.GroupID, Split: g.Metadata.Split, Class: g.Metadata.Class, Profile: g.Metadata.Profile, SourceWorkloadID: g.Metadata.SourceWorkloadID, ClientStack: g.Metadata.ClientStack, Scope: g.Metadata.Scope, Transport: g.Metadata.Transport, ClassifierEmpty: true, Complete: g.Complete, Reasons: g.Reasons, Windows: []WindowDecision{}}
		for _, r := range p.Rules {
			if effective(r, p.Margin) {
				d.ClassifierEmpty = false
			}
		}
		for _, w := range g.Windows {
			v := WindowDecision{Kind: w.Kind, ID: w.ID, FlowID: w.FlowID, Start: w.Start, End: w.End, Eligible: w.Eligible, Scores: w.Scores, Hits: []string{}, RuleEligible: len(w.Scores) > 0}
			if v.RuleEligible {
				d.RuleEligible = true
			}
			if w.Eligible {
				for _, r := range p.Rules {
					if _, ok := w.Scores[r.Rule.ID]; ok && effective(r, p.Margin) {
						v.EnabledRuleEligible = true
						d.EnabledRuleEligible = true
					}
				}
				for _, r := range p.Rules {
					if s, ok := w.Scores[r.Rule.ID]; ok && r.Enabled && s-r.Threshold >= p.Margin {
						v.Hits = append(v.Hits, r.Rule.ID)
					}
				}
			}
			if len(v.Hits) > 0 {
				d.Detected = true
			}
			d.Windows = append(d.Windows, v)
		}
		switch {
		case !d.Complete && d.Detected:
			d.Status = "incomplete_positive_observed"
		case !d.Complete:
			d.Status = "incomplete_undetermined"
		case d.ClassifierEmpty:
			d.Status = "classifier_empty_or_all_rules_disabled_abstain"
		case !d.RuleEligible:
			d.Status = "complete_sparse_or_insufficient_rules_abstain"
		case !d.EnabledRuleEligible:
			d.Status = "enabled_rules_have_no_evidence_abstain"
		case d.Detected:
			d.Status = "detected"
		default:
			d.Status = "not_detected"
		}
		d.Abstained = d.Complete && (d.ClassifierEmpty || !d.RuleEligible || !d.EnabledRuleEligible)
		out = append(out, d)
	}
	return out
}
func measure(ds []Decision) Calibration {
	m := Calibration{Groups: len(ds)}
	flows := map[string]bool{}
	benignFlows, fpFlows := map[string]bool{}, map[string]bool{}
	for _, d := range ds {
		if d.Complete {
			m.Complete++
		} else {
			m.Incomplete++
		}
		if d.Abstained {
			m.Abstain++
		}
		if d.Class == "benign" {
			if d.Complete {
				m.CompleteBenign++
				if d.Detected {
					m.CompleteFP++
				}
			} else {
				m.IncompleteBenign++
			}
			m.Benign++
			if d.Detected {
				m.FP++
			}
			if d.RuleEligible {
				m.RuleEligibleBenign++
			}
		} else {
			if d.Complete {
				m.CompletePositive++
			} else {
				m.IncompletePositive++
			}
			m.Positive++
			if d.Detected {
				m.TP++
			}
		}
		for _, w := range d.Windows {
			m.Windows++
			if w.Eligible {
				m.CoverageEligibleWindows++
			}
			if w.RuleEligible {
				m.RuleEligibleWindows++
			}
			if w.EnabledRuleEligible {
				m.EnabledRuleEligibleWindows++
			}
			key := d.GroupID + "/" + w.FlowID
			flows[key] = true
			if d.Class == "benign" {
				m.BenignWindows++
				benignFlows[key] = true
				if len(w.Hits) > 0 {
					m.WindowFP++
					fpFlows[key] = true
				}
			}
		}
	}
	m.Flows = len(flows)
	m.BenignFlows = len(benignFlows)
	m.FPFlows = len(fpFlows)
	m.CompleteFPR = ratio(m.CompleteFP, m.CompleteBenign)
	m.FPR = ratio(m.FP, m.Benign)
	m.TPR = ratio(m.TP, m.Positive)
	m.EligibleFPR = ratio(m.FP, m.RuleEligibleBenign)
	m.FlowFPR = ratio(m.FPFlows, m.BenignFlows)
	return m
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

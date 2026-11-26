// Command defender jointly calibrates one session OR over all PCAP windows/rules.
// The existing deterministic classical CLI supplies scores; no formula is copied.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

type Assignment struct {
	GroupID string `json:"group_id"`
	Split   string `json:"split"`
	Class   string `json:"class"`
	Profile string `json:"profile"`
}
type Freeze struct {
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
	Schema        int        `json:"schema"`
	Metadata      Metadata   `json:"metadata"`
	Coverage      bool       `json:"coverage_complete"`
	GroupWindows  []Window   `json:"group_windows"`
	Windows       []Window   `json:"windows"`
	GlobalReasons []string   `json:"global_coverage_reasons"`
	PCAPSHA       string     `json:"pcap_sha256"`
	Anchor        *time.Time `json:"group_first_tls23_utc"`
}
type Group struct {
	Metadata  Metadata `json:"metadata"`
	Complete  bool     `json:"coverage_complete"`
	Reasons   []string `json:"coverage_reasons"`
	Windows   []Window `json:"windows"`
	SourceSHA string   `json:"source_sha256"`
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
	Groups             int      `json:"groups"`
	Benign             int      `json:"benign_groups"`
	FP                 int      `json:"false_positive_groups"`
	FPR                *float64 `json:"group_fpr"`
	Positive           int      `json:"positive_groups"`
	TP                 int      `json:"detected_positive_groups"`
	TPR                *float64 `json:"group_tpr"`
	Complete           int      `json:"complete_groups"`
	Incomplete         int      `json:"incomplete_groups"`
	RuleEligibleBenign int      `json:"rule_eligible_benign_groups"`
	EligibleFPR        *float64 `json:"eligible_group_fpr"`
	Abstain            int      `json:"complete_abstaining_groups"`
	Windows            int      `json:"windows"`
	WindowFP           int      `json:"direct_rule_hit_false_positive_windows"`
	BenignWindows      int      `json:"benign_windows"`
	Flows              int      `json:"flows"`
	FPFlows            int      `json:"direct_rule_hit_false_positive_flows"`
	BenignFlows        int      `json:"benign_flows"`
	FlowFPR            *float64 `json:"direct_rule_hit_flow_fpr"`
}
type Policy struct {
	Schema         int                    `json:"schema"`
	Method         string                 `json:"method"`
	FreezeSHA      string                 `json:"freeze_sha256"`
	DefinitionsSHA string                 `json:"definitions_sha256"`
	EngineSHA      string                 `json:"score_engine_sha256"`
	CalibrationSHA string                 `json:"calibration_sha256"`
	Budget         float64                `json:"group_fpr_budget"`
	FlowBudget     float64                `json:"direct_flow_fpr_budget"`
	Margin         float64                `json:"joint_group_margin"`
	Rules          []RulePolicy           `json:"rules"`
	Windows        []int                  `json:"window_offsets_seconds"`
	WindowSeconds  int                    `json:"window_seconds"`
	Cooldown       int                    `json:"cooldown_seconds"`
	Calibration    map[string]Calibration `json:"calibration"`
	Limits         []string               `json:"limits"`
	FrozenAt       time.Time              `json:"policy_frozen_at"`
}
type WindowDecision struct {
	ID           string             `json:"session_id"`
	FlowID       string             `json:"flow_id"`
	Start        time.Time          `json:"window_start_utc"`
	End          time.Time          `json:"window_end_utc"`
	Eligible     bool               `json:"coverage_eligible"`
	RuleEligible bool               `json:"rule_eligible"`
	Hits         []string           `json:"hits"`
	Scores       map[string]float64 `json:"scores"`
}
type Decision struct {
	GroupID      string           `json:"group_id"`
	Split        string           `json:"split"`
	Class        string           `json:"class"`
	Profile      string           `json:"profile"`
	Complete     bool             `json:"coverage_complete"`
	Detected     bool             `json:"any_detected"`
	RuleEligible bool             `json:"rule_eligible"`
	Status       string           `json:"status"`
	Reasons      []string         `json:"coverage_reasons"`
	Windows      []WindowDecision `json:"windows"`
}
type Index struct {
	Reports []string `json:"reports"`
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
func validateFreeze(f Freeze) error {
	if f.Schema != 1 || f.Stage != "B" || f.Viability != "proceed" || f.Frozen.IsZero() {
		return fmt.Errorf("fresh StageB freeze and explicit StageA proceed decision required")
	}
	if f.MeasuredSeconds != 45 || f.CaptureSeconds < 45 || f.CaptureSeconds > 60 || f.WindowSeconds != 2 || f.Cooldown != 30 || f.CaptureCap != 256*1024*1024 || len(f.WindowOffsets) != 4 || f.Budget != 0.05 || f.FlowBudget != 0.05 {
		return fmt.Errorf("freeze timing/capture contract mismatch")
	}
	for i, want := range []int{0, 8, 18, 28} {
		if f.WindowOffsets[i] != want {
			return fmt.Errorf("freeze window schedule mismatch")
		}
	}
	if len(f.DefinitionsSHA) != 64 || len(f.EngineSHA) != 64 || len(f.Groups) == 0 {
		return fmt.Errorf("freeze must pin score engine/definitions and groups")
	}
	seen := map[string]bool{}
	for _, a := range f.Groups {
		if a.GroupID == "" || seen[a.GroupID] || (a.Split != "train" && a.Split != "validation" && a.Split != "test") || (a.Class != "benign" && a.Class != "belnet") || a.Profile == "" {
			return fmt.Errorf("invalid or repeated frozen assignment")
		}
		seen[a.GroupID] = true
	}
	return nil
}
func loadGroups(indexPath string, f Freeze, freezeSHA string, fit bool) ([]Group, error) {
	var index Index
	if _, err := read(indexPath, &index); err != nil {
		return nil, err
	}
	expected := map[string]Assignment{}
	for _, a := range f.Groups {
		expected[a.GroupID] = a
	}
	seen := map[string]bool{}
	groups := []Group{}
	for _, path := range index.Reports {
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(indexPath), path)
		}
		var c Capture
		sourceSHA, err := read(path, &c)
		if err != nil {
			return nil, err
		}
		a, ok := expected[c.Metadata.GroupID]
		if !ok || a != c.Metadata.Assignment || seen[a.GroupID] {
			return nil, fmt.Errorf("unknown/mismatched/repeated frozen group %s", c.Metadata.GroupID)
		}
		seen[a.GroupID] = true
		if fit && a.Split == "test" {
			continue
		}
		if c.Metadata.FreezeSHA != freezeSHA || c.Metadata.CaptureCap != f.CaptureCap || c.Metadata.MeasuredSeconds != f.MeasuredSeconds || !c.Metadata.CaptureStarted.After(f.Frozen) || c.Metadata.CaptureEnded.Sub(c.Metadata.CaptureStarted) < time.Duration(f.CaptureSeconds)*time.Second {
			return nil, fmt.Errorf("group %s lacks pinned fresh capture after freeze", a.GroupID)
		}
		g := Group{Metadata: c.Metadata, Complete: c.Coverage, Reasons: append([]string(nil), c.GlobalReasons...), Windows: []Window{}, SourceSHA: sourceSHA}
		if c.Schema != 1 || len(c.GroupWindows) != 4 || c.Anchor == nil {
			g.Complete = false
			g.Reasons = append(g.Reasons, "observer_schema_or_group_window_count")
		}
		for i, w := range c.GroupWindows {
			if c.Anchor != nil && i < len(f.WindowOffsets) && (!w.Start.Equal(c.Anchor.Add(time.Duration(f.WindowOffsets[i])*time.Second)) || w.End.Sub(w.Start) != 2*time.Second) {
				return nil, fmt.Errorf("declared time-window schedule mismatch in group %s", a.GroupID)
			}
			if !w.Eligible {
				g.Complete = false
				g.Reasons = append(g.Reasons, "incomplete_declared_group_window")
			}
		}
		ids := map[string]bool{}
		for _, w := range c.Windows {
			if w.Status == "not_applicable" {
				continue
			}
			if w.GroupID != a.GroupID || w.Split != a.Split || w.Class != a.Class || w.Profile != a.Profile || w.ID == "" || w.FlowID == "" || ids[w.ID] || w.End.Sub(w.Start) != 2*time.Second {
				return nil, fmt.Errorf("window provenance mismatch in group %s", a.GroupID)
			}
			ids[w.ID] = true
			if !w.Eligible {
				g.Complete = false
				g.Reasons = append(g.Reasons, "incomplete_flow_or_reconnect_window")
			}
			g.Windows = append(g.Windows, w)
		}
		groups = append(groups, g)
	}
	for id, a := range expected {
		if (!fit || a.Split != "test") && !seen[id] {
			return nil, fmt.Errorf("missing declared group %s", id)
		}
	}
	return groups, nil
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
		if g.Metadata.Split == "test" {
			return Policy{}, fmt.Errorf("test groups cannot enter calibration")
		}
		if !g.Complete {
			return Policy{}, fmt.Errorf("incomplete group %s: %v; no silent eligibility filtering", g.Metadata.GroupID, g.Reasons)
		}
	}
	p := Policy{Schema: 1, Method: "session/flow OR MAX across all declared windows,15rules and reconnects", FreezeSHA: freezeSHA, DefinitionsSHA: c.SHA, EngineSHA: f.EngineSHA, Budget: budget, FlowBudget: budget, Windows: f.WindowOffsets, WindowSeconds: f.WindowSeconds, Cooldown: f.Cooldown, Calibration: map[string]Calibration{}, Limits: []string{"Tooling score policy, not a claim of native functional viability", "All windows/reconnects of a group remain in the same split", "Complete sparse windows abstain; censored groups do not become passes", "Both empirical session-OR and direct-rule-hit flow FPR budgets are calibrated jointly", "Direct-rule-hit flow counts exclude collateral blocking from an IP/endpoint cooldown", "30-second persistence is declared policy; live enforcement must be separately measured", "Positive labels denote supplied group class; native payload/nonce eligibility requires external metadata join"}}
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
	if p.FrozenAt.IsZero() || p.Budget != f.Budget || p.FlowBudget != f.FlowBudget || p.Cooldown != f.Cooldown || p.WindowSeconds != f.WindowSeconds || len(p.Rules) != len(c.Rules) || len(p.Windows) != len(f.WindowOffsets) || math.IsNaN(p.Margin) || math.IsInf(p.Margin, 0) || p.Margin < 0 {
		return fmt.Errorf("invalid frozen session policy")
	}
	for i, r := range p.Rules {
		if r.Rule != c.Rules[i] || r.Threshold < 0 || math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Enabled != (r.Threshold <= 1) {
			return fmt.Errorf("invalid frozen rule %d", i+1)
		}
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
		if g.Metadata.Split == "test" && !g.Metadata.CaptureStarted.After(p.FrozenAt) {
			return fmt.Errorf("sealed test capture must start after DPI policy freeze; previous captures are development only")
		}
	}
	return nil
}
func evaluate(groups []Group, p Policy) []Decision {
	out := []Decision{}
	for _, g := range groups {
		d := Decision{GroupID: g.Metadata.GroupID, Split: g.Metadata.Split, Class: g.Metadata.Class, Profile: g.Metadata.Profile, Complete: g.Complete, Reasons: g.Reasons, Windows: []WindowDecision{}}
		for _, w := range g.Windows {
			v := WindowDecision{ID: w.ID, FlowID: w.FlowID, Start: w.Start, End: w.End, Eligible: w.Eligible, Scores: w.Scores, Hits: []string{}, RuleEligible: len(w.Scores) > 0}
			if v.RuleEligible {
				d.RuleEligible = true
			}
			if w.Eligible {
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
		case !d.RuleEligible:
			d.Status = "complete_sparse_or_insufficient_rules_abstain"
		case d.Detected:
			d.Status = "detected"
		default:
			d.Status = "not_detected"
		}
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
		if d.Complete && !d.RuleEligible {
			m.Abstain++
		}
		if d.Class == "benign" {
			m.Benign++
			if d.Detected {
				m.FP++
			}
			if d.RuleEligible {
				m.RuleEligibleBenign++
			}
		} else {
			m.Positive++
			if d.Detected {
				m.TP++
			}
		}
		for _, w := range d.Windows {
			m.Windows++
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
	m.FPR = ratio(m.FP, m.Benign)
	m.TPR = ratio(m.TP, m.Positive)
	m.EligibleFPR = ratio(m.FP, m.RuleEligibleBenign)
	m.FlowFPR = ratio(m.FPFlows, m.BenignFlows)
	return m
}
func main() {
	if len(os.Args) < 2 {
		panic("use fit or evaluate")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	index := fs.String("index", "", "JSON{reports:[observer report paths]}")
	freezePath := fs.String("freeze", "", "fresh StageB frozenmanifest")
	engine := fs.String("engine", "out/dpi-g01/tooling/classical", "pinned existing classicalCLI")
	output := fs.String("out", "", "output JSON")
	policyPath := fs.String("policy", "", "frozen group-OR policy for evaluate")
	work := fs.String("work", "out/dpi-g01/tooling/work", "score workspace")
	budget := fs.Float64("budget", 0.05, "group OR calibration budget")
	must(fs.Parse(os.Args[2:]))
	if *index == "" || *freezePath == "" || *output == "" {
		panic("-index -freeze -out required")
	}
	var f Freeze
	freezeSHA, err := read(*freezePath, &f)
	must(err)
	must(validateFreeze(f))
	if *budget != f.Budget {
		panic("CLI budget cannot change the frozen group FPR budget")
	}
	raw, err := os.ReadFile(*engine)
	must(err)
	if sha(raw) != f.EngineSHA {
		panic("score engine SHA mismatch")
	}
	must(os.MkdirAll(*work, 0700))
	scratch, err := os.MkdirTemp(*work, "session-or-")
	must(err)
	defer os.RemoveAll(scratch)
	c, err := catalog(*engine, scratch)
	must(err)
	if c.SHA != f.DefinitionsSHA {
		panic("definitions SHA mismatch")
	}
	isFit := os.Args[1] == "fit"
	groups, err := loadGroups(*index, f, freezeSHA, isFit)
	must(err)
	must(scoreGroups(groups, *engine, scratch, c))
	switch os.Args[1] {
	case "fit":
		p, err := calibrate(groups, c, f, freezeSHA, *budget)
		if err != nil {
			_ = write(*output+".rejected.json", map[string]any{"error": err.Error(), "scored_groups": groups, "freeze_sha256": freezeSHA})
			must(err)
		}
		p.FrozenAt = time.Now().UTC()
		must(write(*output, p))
		must(write(*output+".calibration.json", groups))
		fmt.Printf("joint calibrated%dgroups (allwindows/rules/reconnects);testexcluded\n", len(groups))
	case "evaluate":
		var p Policy
		_, err := read(*policyPath, &p)
		must(err)
		if p.Schema != 1 || p.FreezeSHA != freezeSHA || p.DefinitionsSHA != c.SHA || p.EngineSHA != f.EngineSHA {
			panic("policy provenance mismatch")
		}
		must(validatePolicy(p, c, f))
		must(validateTestChronology(groups, p))
		ds := evaluate(groups, p)
		bySplit := map[string][]Decision{}
		byProfile := map[string][]Decision{}
		for _, d := range ds {
			bySplit[d.Split] = append(bySplit[d.Split], d)
			byProfile[d.Profile] = append(byProfile[d.Profile], d)
		}
		splits, profiles := map[string]Calibration{}, map[string]Calibration{}
		for name, d := range bySplit {
			splits[name] = measure(d)
		}
		for name, d := range byProfile {
			profiles[name] = measure(d)
		}
		must(write(*output, map[string]any{"schema": 1, "policy": p, "all": measure(ds), "by_split": splits, "by_profile": profiles, "decisions": ds}))
		fmt.Printf("evaluated%dgroups;incomplete remainsundetermined\n", len(groups))
	default:
		panic("use fit or evaluate")
	}
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

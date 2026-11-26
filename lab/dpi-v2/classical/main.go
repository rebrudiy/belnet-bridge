// Explicit deterministic traffic hypotheses. No payload, endpoint or learned forest.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

type Event struct {
	At        int64 `json:"at_micros"`
	Direction int   `json:"direction"`
	Bytes     int   `json:"bytes"`
}
type Observation struct {
	SessionID string  `json:"session_id"`
	GroupID   string  `json:"group_id"`
	Split     string  `json:"split"`
	Class     string  `json:"class"`
	Profile   string  `json:"profile"`
	Offset    int64   `json:"window_offset_micros,omitempty"`
	Events    []Event `json:"events"`
}
type Rule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Response   string `json:"transport_hypothesis"`
}

var rules = []Rule{
	{"r01", "uplink modal length", "max exact-length count / uplink records; >=8 uplink records", "Vary uplink cell lengths."},
	{"r02", "downlink modal length", "max exact-length count / downlink records; >=8 downlink records", "Vary downlink cell lengths independently."},
	{"r03", "shared modal length", "max_L min(uplink_fraction[L], downlink_fraction[L]); >=8 each direction", "Remove persistent identical request/reply sizes."},
	{"r04", "low length entropy", "1 - Shannon entropy(length)/log2(record count); >=16 total records", "Broaden the length distribution rather than only changing one fixed size."},
	{"r05", "strict direction alternation", "adjacent direction changes / adjacent pairs; >=16 records", "Permit asymmetric and burst delivery."},
	{"r06", "equal opposite-direction neighbors", "opposite-direction adjacent equal-length pairs / all adjacent pairs; >=16 records", "Decouple request/reply lengths."},
	{"r07", "regular uplink clock", "1/(1+CV(positive uplink gaps)); >=8 gaps and >=200 ms span", "Jitter uplink cadence."},
	{"r08", "regular downlink clock", "1/(1+CV(positive downlink gaps)); >=8 gaps and >=200 ms span", "Avoid a separate fixed downlink clock."},
	{"r09", "uplink phase grid", "max circular phase concentration at fixed10/20/25/40/45/50/100 ms grids; >=9 uplink records, span>=200 ms", "Use nonperiodic timing; uniform jitter can leave a detectable phase grid."},
	{"r10", "immediate paired reply", "uplink immediately followed by downlink within10 ms / uplink count; >=8 uplink and >=16 total", "Decouple server reply timing from each poll where operationally acceptable."},
	{"r11", "narrow uplink padding band", "1-(q90(length)-q10(length))/(q90(length)+q10(length)); >=10 uplink records", "Use a wider measured size mixture."},
	{"r12", "two dominant lengths", "mass of two most frequent exact lengths / all records; >=16 records", "Avoid a two-size mixture that only replaces one fixed size."},
	{"r13", "frequent small uplink records", "fraction uplink records<=512 bytes; >=8 uplink records, span>=200 ms", "Measure idle polling leakage; reduce unnecessary small periodic writes."},
	{"r14", "duplex byte symmetry", "1-abs(up_bytes-down_bytes)/(up_bytes+down_bytes); >=16 records, >=4 each direction", "Avoid forced byte symmetry when real workloads are asymmetric."},
	{"r15", "sustained fixed-cell polling", "min(shared modal length, direction alternation, fraction occupied200 ms bins having both directions); >=3 occupied bins and >=8 each direction", "Combine length, timing and directional changes; changing one feature may leave the composite signature."},
}

type RulePolicy struct {
	Rule      Rule    `json:"rule"`
	Threshold float64 `json:"threshold"`
	Enabled   bool    `json:"enabled"`
}
type Round struct {
	Number      int                `json:"number"`
	AddedRule   string             `json:"added_rule"`
	Margin      float64            `json:"joint_margin"`
	Rules       []RulePolicy       `json:"rules"`
	Calibration map[string]Metrics `json:"calibration"`
}
type Policy struct {
	Schema         int          `json:"schema"`
	DefinitionsSHA string       `json:"definitions_sha256"`
	CalibrationSHA string       `json:"calibration_sha256"`
	Budget         float64      `json:"fpr_budget"`
	Rules          []RulePolicy `json:"individual_rules"`
	Rounds         []Round      `json:"rounds"`
	Limits         []string     `json:"limits"`
}
type Metrics struct {
	Observations   int      `json:"observations"`
	Benign         int      `json:"benign"`
	Belnet         int      `json:"belnet"`
	FP             int      `json:"fp"`
	TP             int      `json:"tp"`
	TN             int      `json:"tn"`
	FN             int      `json:"fn"`
	FPR            *float64 `json:"fpr"`
	TPR            *float64 `json:"tpr"`
	BenignGroups   int      `json:"benign_groups"`
	FPBenignGroups int      `json:"fp_benign_groups"`
	GroupFPR       *float64 `json:"group_fpr"`
	EligibleBenign int      `json:"eligible_benign"`
	EligibleBelnet int      `json:"eligible_belnet"`
	EligibleFPR    *float64 `json:"eligible_fpr"`
}
type Decision struct {
	SessionID string             `json:"session_id"`
	GroupID   string             `json:"group_id"`
	Split     string             `json:"split"`
	Class     string             `json:"class"`
	Profile   string             `json:"profile"`
	Window    int64              `json:"window_offset_micros"`
	Round     int                `json:"round"`
	Detected  bool               `json:"detected"`
	Hits      []string           `json:"hits"`
	Scores    map[string]float64 `json:"scores"`
}

func definitionsSHA() string { b, _ := json.Marshal(rules); return fmt.Sprintf("%x", sha256.Sum256(b)) }
func group(o Observation) string {
	if o.GroupID != "" {
		return o.GroupID
	}
	return o.SessionID
}
func events(o Observation, offset int64) []Event {
	result := []Event{}
	base := offset - o.Offset
	if base < 0 {
		return result
	}
	for _, e := range o.Events {
		if e.At >= base && e.At < base+2_000_000 {
			e.At -= base
			result = append(result, e)
			if len(result) == 64 {
				break
			}
		}
	}
	return result
}
func countLengths(e []Event, direction int) map[int]int {
	c := map[int]int{}
	for _, v := range e {
		if direction == 0 || v.Direction == direction {
			c[v.Bytes]++
		}
	}
	return c
}
func directionEvents(e []Event, direction int) []Event {
	r := []Event{}
	for _, v := range e {
		if v.Direction == direction {
			r = append(r, v)
		}
	}
	return r
}
func mass(c map[int]int, top int) float64 {
	n := 0
	a := []int{}
	for _, v := range c {
		n += v
		a = append(a, v)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(a)))
	s := 0
	for i := 0; i < len(a) && i < top; i++ {
		s += a[i]
	}
	if n == 0 {
		return -1
	}
	return float64(s) / float64(n)
}
func alternation(e []Event) float64 {
	n := 0
	for i := 1; i < len(e); i++ {
		if e[i].Direction != e[i-1].Direction {
			n++
		}
	}
	return float64(n) / float64(len(e)-1)
}
func shared(e []Event) float64 {
	up, down := directionEvents(e, 1), directionEvents(e, -1)
	if len(up) < 8 || len(down) < 8 {
		return -1
	}
	u, d := countLengths(up, 0), countLengths(down, 0)
	best := 0.0
	for size, n := range u {
		best = math.Max(best, math.Min(float64(n)/float64(len(up)), float64(d[size])/float64(len(down))))
	}
	return best
}
func regularity(e []Event) float64 {
	if len(e) < 9 || e[len(e)-1].At-e[0].At < 200_000 {
		return -1
	}
	g := []float64{}
	mean := 0.0
	for i := 1; i < len(e); i++ {
		delta := e[i].At - e[i-1].At
		if delta > 0 {
			g = append(g, float64(delta))
			mean += float64(delta)
		}
	}
	if len(g) < 8 {
		return -1
	}
	mean /= float64(len(g))
	variance := 0.0
	for _, v := range g {
		variance += (v - mean) * (v - mean)
	}
	return 1 / (1 + math.Sqrt(variance/float64(len(g)))/mean)
}
func score(index int, e []Event) float64 {
	up, down := directionEvents(e, 1), directionEvents(e, -1)
	switch index {
	case 0:
		if len(up) >= 8 {
			return mass(countLengths(up, 0), 1)
		}
	case 1:
		if len(down) >= 8 {
			return mass(countLengths(down, 0), 1)
		}
	case 2:
		return shared(e)
	case 3:
		if len(e) >= 16 {
			entropy := 0.0
			counts := countLengths(e, 0)
			lengths := make([]int, 0, len(counts))
			for length := range counts {
				lengths = append(lengths, length)
			}
			sort.Ints(lengths)
			// Floating-point summation order must be stable: calibration uses a
			// one-ULP strict cutoff, and Go map iteration deliberately varies.
			for _, length := range lengths {
				n := counts[length]
				p := float64(n) / float64(len(e))
				entropy -= p * math.Log2(p)
			}
			return math.Max(0, 1-entropy/math.Log2(float64(len(e))))
		}
	case 4:
		if len(e) >= 16 {
			return alternation(e)
		}
	case 5:
		if len(e) >= 16 {
			n := 0
			for i := 1; i < len(e); i++ {
				if e[i].Direction != e[i-1].Direction && e[i].Bytes == e[i-1].Bytes {
					n++
				}
			}
			return float64(n) / float64(len(e)-1)
		}
	case 6:
		return regularity(up)
	case 7:
		return regularity(down)
	case 8:
		if len(up) >= 9 && up[len(up)-1].At-up[0].At >= 200_000 {
			best := 0.0
			for _, period := range []float64{10_000, 20_000, 25_000, 40_000, 45_000, 50_000, 100_000} {
				x, y := 0.0, 0.0
				for _, v := range up {
					phase := 2 * math.Pi * float64(v.At) / period
					x += math.Cos(phase)
					y += math.Sin(phase)
				}
				best = math.Max(best, math.Hypot(x, y)/float64(len(up)))
			}
			return best
		}
	case 9:
		if len(up) >= 8 && len(e) >= 16 {
			n := 0
			for i := 1; i < len(e); i++ {
				if e[i-1].Direction == 1 && e[i].Direction == -1 && e[i].At-e[i-1].At <= 10_000 {
					n++
				}
			}
			return float64(n) / float64(len(up))
		}
	case 10:
		if len(up) >= 10 {
			a := make([]int, len(up))
			for i, v := range up {
				a[i] = v.Bytes
			}
			sort.Ints(a)
			lo, hi := float64(a[len(a)/10]), float64(a[(len(a)-1)*9/10])
			return 1 - (hi-lo)/(hi+lo)
		}
	case 11:
		if len(e) >= 16 {
			return mass(countLengths(e, 0), 2)
		}
	case 12:
		if len(up) >= 8 && up[len(up)-1].At-up[0].At >= 200_000 {
			n := 0
			for _, v := range up {
				if v.Bytes <= 512 {
					n++
				}
			}
			return float64(n) / float64(len(up))
		}
	case 13:
		if len(e) >= 16 && len(up) >= 4 && len(down) >= 4 {
			u, d := 0.0, 0.0
			for _, v := range up {
				u += float64(v.Bytes)
			}
			for _, v := range down {
				d += float64(v.Bytes)
			}
			return 1 - math.Abs(u-d)/(u+d)
		}
	case 14:
		if shared(e) >= 0 {
			bins := map[int64]int{}
			for _, v := range e {
				bit := 1
				if v.Direction == -1 {
					bit = 2
				}
				bins[v.At/200_000] |= bit
			}
			if len(bins) >= 3 {
				paired := 0
				for _, mask := range bins {
					if mask == 3 {
						paired++
					}
				}
				return math.Min(shared(e), math.Min(alternation(e), float64(paired)/float64(len(bins))))
			}
		}
	}
	return -1 // insufficient evidence is an abstention, never a positive score.
}
func values(o Observation, offset int64) []float64 {
	e := events(o, offset)
	s := make([]float64, len(rules))
	for i := range s {
		s[i] = score(i, e)
	}
	return s
}
func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	v := float64(n) / float64(d)
	return &v
}
func decision(o Observation, p []RulePolicy, margin float64, offset int64) (bool, bool, []string, map[string]float64) {
	s := values(o, offset)
	eligible := false
	hits := []string{}
	scores := map[string]float64{}
	for i, r := range p {
		if s[i] >= 0 {
			eligible = true
			scores[r.Rule.ID] = s[i]
		}
		// Compare in the same subtraction domain as joint calibration: adding a
		// nextafter-sized margin back to a threshold can round onto a forbidden tie.
		if r.Enabled && s[i] >= 0 && s[i]-r.Threshold >= margin {
			hits = append(hits, r.Rule.ID)
		}
	}
	return len(hits) > 0, eligible, hits, scores
}
func measure(obs []Observation, p []RulePolicy, margin float64, offset int64) Metrics {
	m := Metrics{Observations: len(obs)}
	groups, hitGroups := map[string]bool{}, map[string]bool{}
	for _, o := range obs {
		hit, eligible, _, _ := decision(o, p, margin, offset)
		if o.Class == "benign" {
			m.Benign++
			groups[group(o)] = true
			if hit {
				m.FP++
				hitGroups[group(o)] = true
			}
			if eligible {
				m.EligibleBenign++
			}
		} else {
			m.Belnet++
			if hit {
				m.TP++
			}
			if eligible {
				m.EligibleBelnet++
			}
		}
	}
	m.BenignGroups = len(groups)
	m.FPBenignGroups = len(hitGroups)
	m.FPR = ratio(m.FP, m.Benign)
	m.TPR = ratio(m.TP, m.Belnet)
	m.GroupFPR = ratio(m.FPBenignGroups, m.BenignGroups)
	m.TN, m.FN = m.Benign-m.FP, m.Belnet-m.TP
	m.EligibleFPR = ratio(m.FP, m.EligibleBenign)
	return m
}

func validatePolicy(p Policy) error {
	if p.Schema != 1 || p.DefinitionsSHA != definitionsSHA() || len(p.Rules) < 1 || len(p.Rules) > len(rules) || len(p.Rounds) != len(p.Rules) {
		return fmt.Errorf("policy/schema definition mismatch")
	}
	for i, r := range p.Rules {
		if r.Rule != rules[i] || math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Threshold < 0 || r.Enabled != (r.Threshold <= 1) {
			return fmt.Errorf("invalid rule policy %d", i+1)
		}
	}
	for i, r := range p.Rounds {
		if r.Number != i+1 || r.AddedRule != rules[i].ID || len(r.Rules) != i+1 || math.IsNaN(r.Margin) || math.IsInf(r.Margin, 0) || r.Margin < 0 {
			return fmt.Errorf("invalid round policy %d", i+1)
		}
		for j, rule := range r.Rules {
			if rule != p.Rules[j] {
				return fmt.Errorf("round policy rule mismatch")
			}
		}
	}
	return nil
}

// Cutoff is strictly above the first disallowed order statistic; ties never
// consume more than the configured false-positive budget.
func cutoff(scores []float64, budget float64) float64 {
	if len(scores) == 0 {
		return 2
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(scores)))
	allowed := int(math.Floor(float64(len(scores))*budget + 1e-12))
	if allowed >= len(scores) {
		return -1
	}
	return math.Nextafter(scores[allowed], math.Inf(1))
}
func negativeCutoff(obs []Observation, f func(Observation) float64, budget float64) float64 {
	a := []float64{}
	g := map[string]float64{}
	for _, o := range obs {
		if o.Class != "benign" {
			continue
		}
		s := f(o)
		a = append(a, s)
		v, ok := g[group(o)]
		if !ok || s > v {
			g[group(o)] = s
		}
	}
	b := []float64{}
	for _, s := range g {
		b = append(b, s)
	}
	return math.Max(cutoff(a, budget), cutoff(b, budget))
}
func filtered(obs []Observation, split string) []Observation {
	r := []Observation{}
	for _, o := range obs {
		if o.Split == split {
			r = append(r, o)
		}
	}
	return r
}
func validate(obs []Observation) error {
	groups := map[string]string{}
	seen := map[string]bool{}
	for _, o := range obs {
		if o.SessionID == "" || group(o) == "" {
			return fmt.Errorf("missing session/group")
		}
		if seen[o.SessionID] {
			return fmt.Errorf("duplicate session %s", o.SessionID)
		}
		seen[o.SessionID] = true
		if o.Split != "train" && o.Split != "validation" && o.Split != "test" {
			return fmt.Errorf("invalid split")
		}
		if previous, ok := groups[group(o)]; ok && previous != o.Split {
			return fmt.Errorf("group %s leaks across splits", group(o))
		}
		groups[group(o)] = o.Split
		if o.Class != "benign" && o.Class != "belnet" {
			return fmt.Errorf("invalid class")
		}
		last := int64(-1)
		for _, e := range o.Events {
			if e.At < 0 || e.At < last || e.Bytes < 5 || e.Bytes > 65540 || (e.Direction != 1 && e.Direction != -1) {
				return fmt.Errorf("invalid event in %s", o.SessionID)
			}
			last = e.At
		}
	}
	return nil
}
func fit(obs []Observation, budget float64, selected ...int) (Policy, error) {
	limit := len(rules)
	if len(selected) > 0 {
		limit = selected[0]
	}
	if limit < 1 || limit > len(rules) {
		return Policy{}, fmt.Errorf("rule count must be 1..%d", len(rules))
	}
	// Split assignments are provenance, not test features. Reject a source group
	// assigned to both calibration and test without inspecting test events.
	assignments := map[string]string{}
	for _, o := range obs {
		if previous, ok := assignments[group(o)]; ok && previous != o.Split {
			return Policy{}, fmt.Errorf("group %s leaks across splits", group(o))
		}
		assignments[group(o)] = o.Split
	}
	// Discard final test records before inspecting their events or labels.
	calibration := []Observation{}
	for _, o := range obs {
		if o.Split != "test" {
			calibration = append(calibration, o)
		}
	}
	if err := validate(calibration); err != nil {
		return Policy{}, err
	}
	train, val := filtered(calibration, "train"), filtered(calibration, "validation")
	for _, part := range [][]Observation{train, val} {
		benign, positive := 0, 0
		for _, o := range part {
			if o.Class == "benign" {
				benign++
			} else {
				positive++
			}
		}
		if benign == 0 || positive == 0 {
			return Policy{}, fmt.Errorf("train and validation each need benign and BelNet observations")
		}
	}
	source, _ := json.Marshal(calibration)
	p := Policy{Schema: 1, DefinitionsSHA: definitionsSHA(), CalibrationSHA: fmt.Sprintf("%x", sha256.Sum256(source)), Budget: budget, Limits: []string{"15 deterministic hypotheses, not 15 successful transport changes", "2-second/max64 outer TLS type23 records; includes encrypted TLS1.3 handshake", "no JA3/SNI/payload/IP features; handshake fingerprint not evaluated", "native reconnect continuity/auth probing require separate live evidence", "test used only after policy freeze; insufficient events abstain", "FPR is empirical; correlated sockets/group counts limit population claims"}}
	for i, r := range rules[:limit] {
		feature := func(o Observation) float64 { return values(o, 0)[i] }
		t := math.Max(0, math.Max(negativeCutoff(train, feature, budget), negativeCutoff(val, feature, budget)))
		p.Rules = append(p.Rules, RulePolicy{r, t, t <= 1})
	}
	for n := 1; n <= limit; n++ {
		part := append([]RulePolicy(nil), p.Rules[:n]...)
		joint := func(o Observation) float64 {
			s := values(o, 0)
			best := -2.0
			for i, r := range part {
				if r.Enabled && s[i] >= 0 {
					best = math.Max(best, s[i]-r.Threshold)
				}
			}
			return best
		}
		margin := math.Max(0, math.Max(negativeCutoff(train, joint, budget), negativeCutoff(val, joint, budget)))
		round := Round{Number: n, AddedRule: rules[n-1].ID, Margin: margin, Rules: part, Calibration: map[string]Metrics{"train": measure(train, part, margin, 0), "validation": measure(val, part, margin, 0)}}
		p.Rounds = append(p.Rounds, round)
	}
	return p, nil
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func read(path string, dest any) {
	b, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(b, dest))
}
func write(path string, value any) {
	b, err := json.MarshalIndent(value, "", "  ")
	must(err)
	b = append(b, '\n')
	must(os.WriteFile(path, b, 0644))
}
func main() {
	if len(os.Args) < 2 {
		must(fmt.Errorf("use fit or evaluate"))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	input := fs.String("input", "out/dpi-v2/dataset.json", "Observation array")
	output := fs.String("output", "out/dpi-v2/classical/policy.json", "output JSON")
	policyPath := fs.String("policy", "out/dpi-v2/classical/policy.json", "frozen policy")
	split := fs.String("split", "test", "split to evaluate (train,validation,test,all)")
	offset := fs.Int64("offset", 0, "window offset microseconds")
	budget := fs.Float64("budget", 0.05, "flow and group FPR budget")
	ruleLimit := fs.Int("rules", len(rules), "fit exactly the first k declared rules (1..15)")
	must(fs.Parse(os.Args[2:]))
	if *offset < 0 {
		must(fmt.Errorf("window offset must be nonnegative"))
	}
	if os.Args[1] == "catalog" {
		write(*output, map[string]any{"definitions_sha256": definitionsSHA(), "rules": rules})
		return
	}
	var observations []Observation
	read(*input, &observations)
	switch os.Args[1] {
	case "fit":
		if *budget < 0 || *budget >= 1 {
			must(fmt.Errorf("budget must be in [0,1)"))
		}
		p, err := fit(observations, *budget, *ruleLimit)
		must(err)
		write(*output, p)
		calibration := []Observation{}
		for _, o := range observations {
			if o.Split != "test" {
				calibration = append(calibration, o)
			}
		}
		write(*output+".calibration.json", calibration)
		fmt.Printf("frozen %d rules / %d cumulative rounds; SHA %s\n", len(p.Rules), len(p.Rounds), p.CalibrationSHA)
	case "evaluate":
		var p Policy
		read(*policyPath, &p)
		must(validatePolicy(p))
		must(validate(observations))
		chosen := []Observation{}
		for _, o := range observations {
			if *split == "all" || o.Split == *split {
				chosen = append(chosen, o)
			}
		}
		if len(chosen) == 0 {
			must(fmt.Errorf("no observations for split %s", *split))
		}
		summary := map[string]any{"policy_calibration_sha256": p.CalibrationSHA, "definitions_sha256": p.DefinitionsSHA, "split": *split, "window_offset_micros": *offset}
		roundReports := []map[string]any{}
		decisions := []Decision{}
		for _, r := range p.Rounds {
			profiles := map[string][]Observation{}
			for _, o := range chosen {
				profiles[o.Profile] = append(profiles[o.Profile], o)
				hit, _, hits, scores := decision(o, r.Rules, r.Margin, *offset)
				decisions = append(decisions, Decision{o.SessionID, group(o), o.Split, o.Class, o.Profile, *offset, r.Number, hit, hits, scores})
			}
			byProfile := map[string]Metrics{}
			for name, obs := range profiles {
				byProfile[name] = measure(obs, r.Rules, r.Margin, *offset)
			}
			roundReports = append(roundReports, map[string]any{"round": r.Number, "added_rule": r.AddedRule, "metrics": measure(chosen, r.Rules, r.Margin, *offset), "by_profile": byProfile})
		}
		summary["rounds"] = roundReports
		summary["decisions"] = decisions
		summary["handshake"] = map[string]string{"status": "not_evaluated", "reason": "outer-type23 metadata cannot identify encrypted handshake boundaries or JA3"}
		summary["reconnect_persistence_auth_probe"] = map[string]string{"status": "requires_live_run", "reason": "event arrays lack endpoint identity, reconnect association and probe outcomes"}
		write(*output, summary)
		fmt.Printf("evaluated %d observations (%s), window %d; policy unchanged\n", len(chosen), strings.TrimSpace(*split), *offset)
	default:
		must(fmt.Errorf("unknown command"))
	}
}

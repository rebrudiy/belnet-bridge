package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureCatalog() Catalog {
	c := Catalog{SHA: strings.Repeat("a", 64)}
	for i := 1; i <= 15; i++ {
		c.Rules = append(c.Rules, Rule{ID: fmt.Sprintf("r%02d", i), Name: "fixture", Definition: "synthetic test score, no traffic"})
	}
	return c
}
func assignment(id, split, class, profile string) Assignment {
	transport := "ordinary-tls"
	if class == "belnet" {
		transport = "reality"
	}
	return Assignment{GroupID: id, Split: split, Class: class, Profile: profile, SourceWorkloadID: id, Scope: "primary", Transport: transport, ClientStack: "fixture"}
}
func fixtureFreeze() Freeze {
	return Freeze{AnalysisContract: ConservativeAnalysis, OrderingSHA: strings.Repeat("e", 64), WindowDefinitionsSHA: strings.Repeat("a", 64), LongflowDefinitionsSHA: longDefinitionsSHA, LongflowExtractorSHA: strings.Repeat("f", 64), EnsembleSHA: strings.Repeat("1", 64), Schema: 4, Stage: "B1", Viability: "proceed", Frozen: time.Unix(100, 0).UTC(), MeasuredSeconds: 80, CaptureSeconds: 82, PrefixGrace: 2, WindowOffsets: []int{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78}, WindowSeconds: 2, Cooldown: 30, CaptureCap: 256 * 1024 * 1024, DefinitionsSHA: strings.Repeat("a", 64), EngineSHA: strings.Repeat("b", 64), CollectorSHA: strings.Repeat("c", 64), ObserverSHA: strings.Repeat("d", 64), ObserverVersion: "g04-header-observer-v1", ObserverSchema: 6, CoverageSHA: SupportedCoverageSHA, Budget: .05, FlowBudget: .05, Groups: []Assignment{assignment("declared", "train", "benign", "fixture")}}
}
func syntheticGroup(id, split, class string) Group {
	return Group{Metadata: Metadata{Assignment: assignment(id, split, class, "fixture")}, Complete: true, Reasons: []string{}, Windows: []Window{}}
}
func backgroundGroups() []Group {
	groups := []Group{}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 40; i++ {
			g := syntheticGroup(fmt.Sprintf("%s-%02d", split, i), split, "benign")
			scores := map[string]float64{}
			for j := 1; j <= 15; j++ {
				scores[fmt.Sprintf("r%02d", j)] = .1
			}
			g.Windows = append(g.Windows, Window{ID: g.Metadata.GroupID + "-prefix", GroupID: g.Metadata.GroupID, FlowID: "flow0", Eligible: true, Scores: scores})
			groups = append(groups, g)
		}
	}
	return groups
}
func TestJointGroupBudgetAcrossAllWindowsRulesAndReconnects(t *testing.T) {
	groups := backgroundGroups()
	for i := range groups {
		local := i % 40
		for r := 0; r < 15; r++ {
			if local == r*2 || local == r*2+1 {
				groups[i].Windows = append(groups[i].Windows, Window{ID: fmt.Sprintf("%s-late-rule%d", groups[i].Metadata.GroupID, r), GroupID: groups[i].Metadata.GroupID, FlowID: "reconnected-flow", Eligible: true, Scores: map[string]float64{fmt.Sprintf("r%02d", r+1): .9}})
			}
		}
	}
	p, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	before := p
	p.Margin = 0
	uncal := measure(evaluate(groups, p))
	if uncal.FP < 50 {
		t.Fatalf("fixture did not expose inflated per-rule/window union: %+v", uncal)
	}
	for split, m := range before.Calibration {
		if m.FPR == nil || *m.FPR > .05 {
			t.Fatalf("joint group budget exceeded %s %+v", split, m)
		}
	}
}
func TestLateReconnectFlagsGroupOnce(t *testing.T) {
	groups := backgroundGroups()
	p, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	g := syntheticGroup("heldout", "test", "belnet")
	g.Windows = []Window{{ID: "quiet-prefix", FlowID: "flow0", Eligible: true, Scores: map[string]float64{"r01": .1}}, {ID: "late-reconnect", FlowID: "flow1", Eligible: true, Scores: map[string]float64{"r01": .9}}, {ID: "another-late", FlowID: "flow1", Eligible: true, Scores: map[string]float64{"r02": .9}}}
	ds := evaluate([]Group{g}, p)
	m := measure(ds)
	if !ds[0].Detected || m.TP != 1 || m.Groups != 1 || m.Flows != 2 {
		t.Fatal("reconnect lost or group counted repeatedly", m)
	}
}
func TestCompleteSparseAbstainsAndCensoredNeverBecomesPass(t *testing.T) {
	groups := backgroundGroups()
	for i := range groups {
		groups[i].Windows[0].Scores = map[string]float64{}
	}
	p, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	m := measure(evaluate(groups, p))
	if m.FP != 0 || m.Abstain != 80 {
		t.Fatal("sparse is not explicit abstention", m)
	}
	bad := groups[0]
	bad.Complete = false
	bad.Reasons = []string{"byte_censored"}
	if _, err := calibrate(append([]Group{bad}, groups[1:]...), fixtureCatalog(), fixtureFreeze(), "fixture", .05); err == nil {
		t.Fatal("censored calibration group silently filtered")
	}
	d := evaluate([]Group{bad}, p)[0]
	if d.Status != "incomplete_undetermined" || d.Complete {
		t.Fatal("incomplete became pass", d)
	}
}
func TestTestDataCannotEnterCalibration(t *testing.T) {
	groups := backgroundGroups()
	groups[0].Metadata.Split = "test"
	if _, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "fixture", .05); err == nil {
		t.Fatal("test entered fitting")
	}
}
func TestTieCutoffAndDeterminism(t *testing.T) {
	values := []float64{}
	for i := 0; i < 40; i++ {
		values = append(values, float64(i%5)/5)
	}
	cut := cutoff(values, .05)
	hits := 0
	for _, v := range values {
		if v >= cut {
			hits++
		}
	}
	if hits > 2 {
		t.Fatal("ties exceeded group budget")
	}
	p, err := calibrate(backgroundGroups(), fixtureCatalog(), fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 20; attempt++ {
		again, err := calibrate(backgroundGroups(), fixtureCatalog(), fixtureFreeze(), "fixture", .05)
		if err != nil {
			t.Fatal(err)
		}
		if p.Margin != again.Margin {
			t.Fatal("nondeterministic margin")
		}
		for i, r := range p.Rules {
			if r != again.Rules[i] {
				t.Fatal("nondeterministic thresholds")
			}
		}
	}
}
func TestFreezeGatesAndMalformedPolicy(t *testing.T) {
	f := fixtureFreeze()
	if err := validateFreeze(f); err != nil {
		t.Fatal(err)
	}
	f.Viability = "inconclusive"
	if validateFreeze(f) == nil {
		t.Fatal("StageA failure accepted")
	}
	f = fixtureFreeze()
	f.Budget = .5
	if validateFreeze(f) == nil {
		t.Fatal("FP budget silently weakened")
	}
	f = fixtureFreeze()
	f.WindowOffsets = []int{0, 5, 4, 20}
	if validateFreeze(f) == nil {
		t.Fatal("window plan silently changed")
	}
	p, err := calibrate(backgroundGroups(), fixtureCatalog(), fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	p.FrozenAt = time.Now().UTC()
	if err = validatePolicy(p, fixtureCatalog(), fixtureFreeze()); err != nil {
		t.Fatal(err)
	}
	p.Margin = math.NaN()
	if validatePolicy(p, fixtureCatalog(), fixtureFreeze()) == nil {
		t.Fatal("malformed policy accepted")
	}
}
func TestExistingScoreEngineIsReusedExactly(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	engine := filepath.Join(work, "classical")
	cmd := exec.Command("go", "build", "-o", engine, "./lab/dpi-v2/classical")
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build existing engine: %v %s", err, raw)
	}
	c, err := catalog(engine, work)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 15 || len(c.SHA) != 64 {
		t.Fatal("wrong definitions")
	}
	g := syntheticGroup("fixture-score", "train", "benign")
	events := []Event{}
	for i := 0; i < 64; i++ {
		d := 1
		if i%2 == 1 {
			d = -1
		}
		events = append(events, Event{At: int64(i) * 10000, Direction: d, Bytes: 1004})
	}
	g.Windows = []Window{{ID: "fixture-window", GroupID: g.Metadata.GroupID, Split: "train", Class: "benign", Profile: "fixture", FlowID: "flow0", Eligible: true, Events: events}}
	groups := []Group{g}
	if err := scoreGroups(groups, engine, work, c); err != nil {
		t.Fatal(err)
	}
	if groups[0].Windows[0].Scores["r01"] != 1 || groups[0].Windows[0].Scores["r15"] != 1 {
		t.Fatal("existing engine scores were not retained", groups[0].Windows[0].Scores)
	}
	if _, err := os.Stat(filepath.Join(work, "group-0000-scores.json")); err != nil {
		t.Fatal("raw score evidence absent")
	}
}

func TestHighFanoutGroupCannotHideDirectFlowFalsePositives(t *testing.T) {
	groups := backgroundGroups()
	for i := range groups {
		if i%40 != 0 {
			continue
		}
		groups[i].Windows[0].Scores["r01"] = .9
		for flow := 1; flow < 200; flow++ {
			groups[i].Windows = append(groups[i].Windows, Window{ID: fmt.Sprintf("%s-fanout%d", groups[i].Metadata.GroupID, flow), GroupID: groups[i].Metadata.GroupID, FlowID: fmt.Sprintf("flow%d", flow), Eligible: true, Scores: map[string]float64{"r01": .9}})
		}
	}
	// A group-only policy can hit1/40groups while hitting200/239flows.
	loose := Policy{Rules: []RulePolicy{{Rule: fixtureCatalog().Rules[0], Threshold: .2, Enabled: true}}}
	looseMetrics := measure(evaluate(groups, loose))
	if looseMetrics.FPR == nil || *looseMetrics.FPR > .05 || looseMetrics.FlowFPR == nil || *looseMetrics.FlowFPR < .8 {
		t.Fatal("highfanout regression fixture insufficient", looseMetrics)
	}
	policy, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	for split, m := range policy.Calibration {
		if m.FPR == nil || *m.FPR > .05 || m.FlowFPR == nil || *m.FlowFPR > .05 {
			t.Fatalf("jointgroup+flowbudget violated %s %+v", split, m)
		}
	}
}

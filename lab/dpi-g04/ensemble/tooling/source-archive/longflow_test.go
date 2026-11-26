package main

import (
	"fmt"
	"testing"
	"time"
)

func TestJoint23RulesDoesNotGiveEachDetectorFivePercent(t *testing.T) {
	old := fixtureCatalog()
	c, err := combinedCatalog(old, longDefinitionsSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 23 {
		t.Fatal(len(c.Rules))
	}
	groups := backgroundGroups()
	for i := range groups {
		g := &groups[i]
		for r, rule := range c.Rules {
			score := .1
			if i%40 == r {
				score = .9
			}
			g.Windows = append(g.Windows, Window{ID: fmt.Sprintf("%s/long/%d", g.Metadata.GroupID, r), GroupID: g.Metadata.GroupID, FlowID: "flow0", Eligible: true, Scores: map[string]float64{rule.ID: score}})
		}
	}
	p, err := calibrate(groups, c, fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	// Individually admissible 1/40 hits per rule would jointly hit23/40.
	uncal := p
	uncal.Margin = 0
	if m := measure(evaluate(groups, uncal)); m.FP < 40 {
		t.Fatalf("fixture failed to expose OR inflation:%+v", m)
	}
	for split, m := range p.Calibration {
		if m.FPR == nil || *m.FPR > .05 || m.FlowFPR == nil || *m.FlowFPR > .05 {
			t.Fatalf("%s violated joint budget:%+v", split, m)
		}
	}
}
func TestWholeFlowReusesActualFlowDenominator(t *testing.T) {
	g := syntheticGroup("group", "train", "benign")
	g.Metadata.MeasurementStartMicros = 1_000_000
	g.Metadata.MeasuredSeconds = 80
	g.Metadata.FreezeSHA = "collector"
	g.OrderingSHA = fixtureFreeze().OrderingSHA
	g.CoverageSHA = fixtureFreeze().CoverageSHA
	g.PCAPSHA = "pcap"
	g.PrimaryTLSFlows = map[string]bool{"actual-tcp": true}
	g.PrimaryHeaderCounts = map[string]uint64{"actual-tcp": 20}
	g.Windows = []Window{{ID: "prefix", FlowID: "actual-tcp", Eligible: true, Scores: map[string]float64{"r01": .2}}}
	f := fixtureFreeze()
	f.CollectorSHA = "collector"
	f.LongflowDefinitionsSHA = longDefinitionsSHA
	lf := LongFlow{ID: "actual-tcp", Applicable: true, Eligible: true, Features: map[string]LongFeature{}}
	value := .5
	for _, rule := range longRules {
		lf.Features[rule.ID] = LongFeature{Value: &value, Eligible: true, Support: 20}
	}
	r := LongReport{Schema: 4, Version: "g04-header-longflow-v1", CoverageSHA: fixtureFreeze().CoverageSHA, OrderingSHA: fixtureFreeze().OrderingSHA, DefinitionsSHA: longDefinitionsSHA, PCAPSHA: "pcap", Metadata: g.Metadata, Flows: []LongFlow{lf}}
	if err := appendLongReport(&g, r, f); err != nil {
		t.Fatal(err)
	}
	if len(g.Windows) != 2 || g.Windows[1].FlowID != "actual-tcp" || g.Windows[1].End.Sub(g.Windows[1].Start) != 80*time.Second {
		t.Fatal("wholeflow observation corrupted actual TCP identity")
	}
	p := Policy{Rules: []RulePolicy{{Rule: longRules[0], Threshold: .4, Enabled: true}}}
	m := measure(evaluate([]Group{g}, p))
	if m.Flows != 1 || m.BenignFlows != 1 || m.FPFlows != 1 {
		t.Fatalf("pseudo-flow inflated denominator:%+v", m)
	}
}
func TestWholeFlowProvenanceAndAbstention(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	g.Metadata.MeasuredSeconds = 80
	g.PCAPSHA = "expected"
	f := fixtureFreeze()
	f.LongflowDefinitionsSHA = longDefinitionsSHA
	if err := appendLongReport(&g, LongReport{Schema: 4, Version: "g04-header-longflow-v1", CoverageSHA: fixtureFreeze().CoverageSHA, OrderingSHA: fixtureFreeze().OrderingSHA, DefinitionsSHA: longDefinitionsSHA, PCAPSHA: "other", Metadata: g.Metadata}, f); err == nil {
		t.Fatal("different PCAP accepted")
	}
	c1, _ := combinedCatalog(fixtureCatalog(), longDefinitionsSHA)
	c2, _ := combinedCatalog(fixtureCatalog(), longDefinitionsSHA)
	if c1.SHA != c2.SHA {
		t.Fatal("nondeterministic catalog")
	}
	if _, err := combinedCatalog(fixtureCatalog(), "changed"); err == nil {
		t.Fatal("unpinned longflow definitions accepted")
	}
}
func TestNoTLSLongflowCannotInventFeaturesAndValidAttemptRemains(t *testing.T) {
	g := syntheticGroup("group", "train", "benign")
	f := fixtureFreeze()
	f.CollectorSHA = "collector"
	f.LongflowDefinitionsSHA = longDefinitionsSHA
	g.Metadata.MeasurementStartMicros = 1_000_000
	g.Metadata.MeasuredSeconds = 80
	g.Metadata.FreezeSHA = f.CollectorSHA
	g.OrderingSHA = f.OrderingSHA
	g.CoverageSHA = f.CoverageSHA
	g.PCAPSHA = "pcap"
	g.PrimaryFlowIDs = []string{"noTLS"}
	g.PrimaryTLSFlows = map[string]bool{"noTLS": false}
	g.Windows = []Window{{ID: "sparse", FlowID: "noTLS", Eligible: true}}
	r := LongReport{Schema: 4, Version: "g04-header-longflow-v1", OrderingSHA: f.OrderingSHA, CoverageSHA: f.CoverageSHA, DefinitionsSHA: longDefinitionsSHA, PCAPSHA: g.PCAPSHA, Metadata: g.Metadata, Flows: []LongFlow{{ID: "noTLS", Applicable: false}}}
	if err := appendLongReport(&g, r, f); err != nil {
		t.Fatal("valid observed noTLS attempt rejected", err)
	}
	if len(g.Windows) != 1 {
		t.Fatal("fake LF feature window added")
	}
	r.Flows[0].Applicable = true
	r.Flows[0].Eligible = true
	if err := appendLongReport(&g, r, f); err == nil {
		t.Fatal("LF active on noTLS inventory accepted")
	}
}

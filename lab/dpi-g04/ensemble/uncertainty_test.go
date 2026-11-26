package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func uncertainBackground(n int) []Group {
	groups := backgroundGroups()
	for i := range groups {
		g := &groups[i]
		g.PrimaryFlowIDs = []string{"flow0"}
		if i%40 < n {
			g.Complete = false
			g.UncertaintyBounded = true
			g.AffectedFlowIDs = []string{"flow0"}
			g.Reasons = []string{"synthetic-semantic-fault"}
		}
	}
	return groups
}
func TestUnknownUnionCountsAlreadyObservedHitOnce(t *testing.T) {
	groups := uncertainBackground(1)
	for i := range groups {
		if i%40 < 2 {
			groups[i].Windows[0].Scores["r01"] = .9
		}
	}
	p, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "synthetic", .05)
	if err != nil {
		t.Fatal(err)
	}
	for split, m := range p.Calibration {
		if m.WorstFP != 2 || m.FP != 2 || m.WorstFPFlows != 2 || m.UnboundedBenign != 0 || m.WorstFPR == nil || *m.WorstFPR != .05 || m.WorstFlowFPR == nil || *m.WorstFlowFPR != .05 {
			t.Fatalf("unknown doublecount/reservation wrong %s:%+v", split, m)
		}
	}
}
func TestUnknownWithoutHitStillConsumesBudgetBeforeCalibration(t *testing.T) {
	groups := uncertainBackground(1)
	for i := range groups {
		if i%40 == 1 {
			groups[i].Windows[0].Scores["r01"] = .9
		}
	}
	p, err := calibrate(groups, fixtureCatalog(), fixtureFreeze(), "synthetic", .05)
	if err != nil {
		t.Fatal(err)
	}
	for split, m := range p.Calibration {
		if m.WorstFP != 2 || m.FP != 1 || m.WorstFPFlows != 2 || m.FPFlows != 1 {
			t.Fatalf("missing uncertainty FP %s:%+v", split, m)
		}
	}
}
func TestFloorOrUnboundedInventoryIsTypedInconclusive(t *testing.T) {
	for _, kind := range []string{"group-floor", "flow-floor", "inventory"} {
		g := uncertainBackground(1)
		switch kind {
		case "group-floor":
			g = uncertainBackground(3)
		case "flow-floor":
			for i := range g {
				if i%40 != 0 {
					g[i].PrimaryFlowIDs = nil
					g[i].Windows = nil
				}
			}
		case "inventory":
			g[0].UncertaintyBounded = false
		}
		_, err := calibrate(g, fixtureCatalog(), fixtureFreeze(), "synthetic", .05)
		var typed *InconclusiveError
		if !errors.As(err, &typed) || !strings.Contains(err.Error(), "no certified policy") {
			t.Fatalf("%s produced wrong error:%v", kind, err)
		}
	}
}
func TestSemanticMappingRequiresEveryReasonAndPreservesActualInventory(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	g.Complete = false
	g.PrimaryFlowIDs = []string{"good", "broken"}
	g.Reasons = []string{"observer_coverage_incomplete", "primary_flow_fault: partial_final_tls_record", "incomplete_flow_or_reconnect_window"}
	b := true
	c := Capture{GlobalReasons: []string{"primary_flow_fault: partial_final_tls_record"}, Flows: []FlowSummary{{ID: "good", PrimaryScope: &b}, {ID: "broken", PrimaryScope: &b, Issues: []string{"partial_final_tls_record"}}}, Windows: []Window{{FlowID: "broken", Primary: true, Status: "incomplete", Eligible: false, Reasons: []string{"partial_final_tls_record"}}}}
	setUncertainty(&g, c)
	if !g.UncertaintyBounded || len(g.AffectedFlowIDs) != 1 || g.AffectedFlowIDs[0] != "broken" || g.Complete {
		t.Fatal("semantic unknown mapping upgraded/excluded", g)
	}
	g.Reasons = append(g.Reasons, "collector_coverage: kernel_drops")
	g.AffectedFlowIDs = nil
	g.UncertaintyBounded = false
	setUncertainty(&g, c)
	if g.UncertaintyBounded || len(g.AffectedFlowIDs) != 2 {
		t.Fatal("capture fault trusted a convenient denominator", g)
	}
}
func TestIncompletePositiveHitsAreOnlyObservedLowerBound(t *testing.T) {
	g := syntheticGroup("g", "test", "belnet")
	g.UncertaintyBounded = true
	g.Complete = false
	g.PrimaryFlowIDs = []string{"a"}
	g.Windows = []Window{{ID: "valid", FlowID: "a", Eligible: true, Scores: map[string]float64{"r01": .9}}, {ID: "bad", FlowID: "a", Eligible: false, Scores: map[string]float64{"r02": 1}}}
	p := Policy{Rules: []RulePolicy{{Rule: Rule{ID: "r01"}, Threshold: .5, Enabled: true}, {Rule: Rule{ID: "r02"}, Threshold: .5, Enabled: true}}}
	d := evaluate([]Group{g}, p)[0]
	if d.Status != "incomplete_positive_observed" || !d.Detected || len(d.Windows[1].Hits) != 0 {
		t.Fatal("invalid view scored or coverage upgraded", d)
	}
	m := measure([]Decision{d})
	if m.TP != 1 || m.IncompletePositive != 1 || m.WorstFP != 0 {
		t.Fatal("positive uncertainty counted as ordinary FP", m)
	}
}

func TestUnmappedOrEmptyGroupWindowCannotBeLocalizedByAnotherFlowFault(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	g.Complete = false
	g.PrimaryFlowIDs = []string{"good", "broken"}
	g.Reasons = []string{"observer_coverage_incomplete", "primary_flow_fault: partial_final_tls_record", "incomplete_declared_group_window"}
	c := Capture{GlobalReasons: []string{"primary_flow_fault: partial_final_tls_record"}, Flows: []FlowSummary{{ID: "broken", Issues: []string{"partial_final_tls_record"}}, {ID: "good"}}}
	for _, reason := range []string{"packet_snaplen_censored", ""} {
		w := Window{Eligible: false, Primary: true}
		if reason != "" {
			w.Reasons = []string{reason}
		}
		c.GroupWindows = []Window{w}
		g.UncertaintyBounded = true
		g.AffectedFlowIDs = []string{"broken"}
		setUncertainty(&g, c)
		if g.UncertaintyBounded || len(g.AffectedFlowIDs) != 2 {
			t.Fatalf("unmapped group cause localized:%q %+v", reason, g)
		}
	}
	c.GroupWindows[0].Reasons = []string{"partial_final_tls_record"}
	setUncertainty(&g, c)
	if !g.UncertaintyBounded || len(g.AffectedFlowIDs) != 1 {
		t.Fatal("mapped group cause rejected", g)
	}
}
func TestMissingLongflowViewAffectsAllKnownFlows(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	g.Complete = false
	g.UncertaintyBounded = true
	g.PrimaryFlowIDs = []string{"a", "b"}
	g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
	g.Metadata.MeasurementStartMicros = time.Unix(100, 0).UnixMicro()
	m := measure(evaluate([]Group{g}, Policy{}))
	if m.WorstFPFlows != 2 || m.WorstFlowFPR == nil || *m.WorstFlowFPR != 1 {
		t.Fatal("unknown missing-view flows disappeared", m)
	}
}

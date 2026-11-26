package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorUnionKeepsOriginalChronologyAndExactMembership(t *testing.T) {
	f := fixtureFreeze()
	f.Frozen = time.Unix(300, 0)
	f.Groups[0].CollectorSHA = ""
	base := collectorManifest{Schema: "belnet-g03-collector/v4", Stage: "B1", Frozen: time.Unix(100, 0), Groups: f.Groups, Measured: 80, Capture: 82, Grace: 2, Offsets: f.WindowOffsets, Cap: f.CaptureCap}
	file := filepath.Join(t.TempDir(), "collector.json")
	if err := write(file, base); err != nil {
		t.Fatal(err)
	}
	var readback collectorManifest
	digest, err := read(file, &readback)
	if err != nil {
		t.Fatal(err)
	}
	f.Collectors = []CollectorBinding{{Path: file, SHA: digest}}
	f.CollectorSHA = digest
	f.Groups[0].CollectorSHA = digest
	origins, err := captureOrigins(f, "")
	if err != nil {
		t.Fatal(err)
	}
	if !origins[f.Groups[0].GroupID].Frozen.Equal(base.Frozen) {
		t.Fatal("used later union-policy freeze for original capture")
	}
	for _, kind := range []string{"hash", "source", "split", "missing", "future"} {
		g := f
		g.Groups = append([]Assignment(nil), f.Groups...)
		g.Collectors = append([]CollectorBinding(nil), f.Collectors...)
		switch kind {
		case "hash":
			g.Collectors[0].SHA = strings.Repeat("f", 64)
		case "source":
			g.Groups[0].SourceWorkloadID = "wrong"
		case "split":
			g.Groups[0].Split = "validation"
		case "missing":
			g.Groups = append(g.Groups, assignment("absent", "train", "belnet", "x"))
			g.Groups[1].CollectorSHA = digest
		case "future":
			g.Frozen = time.Unix(99, 0)
		}
		if _, err := captureOrigins(g, ""); err == nil {
			t.Fatalf("accepted%s", kind)
		}
	}
}

func recipeFixture() []EngineeredRule {
	return []EngineeredRule{{ID: "a01", Name: "synthetic conjunction", Hypothesis: "Explicit synthetic-only marker test", EvidenceSHA: strings.Repeat("a", 64), Terms: []FeatureTerm{{Source: "r01", Shape: "high", Lower: .2, Upper: .8}, {Source: "r02", Shape: "low", Lower: .2, Upper: .8}}}}
}

func TestEngineeredConjunctionStaysWithinActualFlowAndMissingAbstains(t *testing.T) {
	rules := recipeFixture()
	g := syntheticGroup("g", "train", "benign")
	g.PrimaryFlowIDs = []string{"a", "b", "syn-only"}
	g.Windows = []Window{{ID: "a", FlowID: "a", Eligible: true, Scores: map[string]float64{"r01": .8}}, {ID: "b", FlowID: "b", Eligible: true, Scores: map[string]float64{"r02": .2}}}
	groups := []Group{g}
	addEngineeredScores(groups, rules)
	for _, w := range groups[0].Windows {
		if _, ok := w.Scores["a01"]; ok {
			t.Fatal("cross-flow aggregation or fabricated missing evidence")
		}
	}
	groups[0].Windows = append(groups[0].Windows, Window{ID: "a-late", FlowID: "a", Eligible: true, Scores: map[string]float64{"r02": .2}})
	addEngineeredScores(groups, rules)
	found := false
	for _, w := range groups[0].Windows {
		if value, ok := w.Scores["a01"]; ok {
			found = true
			if w.FlowID != "a" || value != 1 {
				t.Fatal("incorrect conjunction", w)
			}
		}
	}
	if !found {
		t.Fatal("eligible explicit rule never evaluated")
	}
	if len(groups[0].PrimaryFlowIDs) != 3 {
		t.Fatal("actual population changed")
	}
}

func TestEngineeredDefinitionsBindEveryTermAndRemainJointlyCalibrated(t *testing.T) {
	base := fixtureCatalog()
	recipes := recipeFixture()
	c, err := engineeredCatalog(base, recipes)
	if err != nil {
		t.Fatal(err)
	}
	other := recipeFixture()
	other[0].Terms[0].Upper = .9
	changed, err := engineeredCatalog(base, other)
	if err != nil || changed.SHA == c.SHA {
		t.Fatal("manual rule formula not bound")
	}
	bad := recipeFixture()
	bad[0].Terms[1].Source = "metadata-label"
	if _, err := engineeredCatalog(base, bad); err == nil {
		t.Fatal("label/unknown feature accepted")
	}
	groups := backgroundGroups()
	for i := range groups {
		groups[i].PrimaryFlowIDs = []string{"flow0"}
		groups[i].Windows[0].Scores["r02"] = .2
		if i%40 < 20 {
			groups[i].Windows[0].Scores["r01"] = .8
		}
	}
	addEngineeredScores(groups, recipes)
	p, err := calibrate(groups, c, fixtureFreeze(), "fixture", .05)
	if err != nil {
		t.Fatal(err)
	}
	for split, m := range p.Calibration {
		if m.FPR == nil || *m.FPR > .05 || m.FlowFPR == nil || *m.FlowFPR > .05 {
			t.Fatalf("engineered OR inflation %s:%+v", split, m)
		}
	}
}

func TestPolicyRecipeRoundTripAllowsEmptyButBindsNonemptyDefinitions(t *testing.T) {
	f := fixtureFreeze()
	f.EngineeredRules = []EngineeredRule{}
	p := Policy{FreezeSHA: "fixture", LastDevelopmentCapture: time.Unix(100, 0), FrozenAt: time.Unix(200, 0)}
	if err := policyBinding(p, f, "fixture", ""); err != nil {
		t.Fatal("omitempty nil/empty round-trip rejected", err)
	}
	f.EngineeredRules = recipeFixture()
	p.EngineeredRules = recipeFixture()
	if err := policyBinding(p, f, "fixture", ""); err != nil {
		t.Fatal(err)
	}
	p.EngineeredRules[0].Terms[0].Upper = .9
	if err := policyBinding(p, f, "fixture", ""); err == nil {
		t.Fatal("changed explicit formula accepted")
	}
}

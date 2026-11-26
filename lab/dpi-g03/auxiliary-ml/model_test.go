package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func assigned(id, split, class string) Assignment {
	transport := "ordinary-tls"
	if class == "belnet" {
		transport = "reality"
	}
	return Assignment{GroupID: id, Split: split, Class: class, Profile: "synthetic-only", SourceWorkloadID: id, Scope: "primary", Transport: transport, ClientStack: "fixture"}
}
func fixtureGroup(id, split, class string, length int) Group {
	a := assigned(id, split, class)
	start := time.Unix(200, 0).UTC()
	g := Group{Metadata: Metadata{Assignment: a, CaptureStarted: start, CaptureEnded: start.Add(82 * time.Second)}, Complete: true, Reasons: []string{}, PrimaryTLSFlows: map[string]bool{"tcp0": true}}
	w := Window{ID: id + "/prefix", GroupID: id, Split: split, Class: class, Profile: a.Profile, FlowID: "tcp0", Kind: "flow-prefix", Start: start.Add(time.Second), End: start.Add(3 * time.Second), Primary: true, Eligible: true, Status: "complete", MaskedRules: []string{}}
	for i := 0; i < 32; i++ {
		d := 1
		if i%2 == 1 {
			d = -1
		}
		w.Events = append(w.Events, Event{At: int64(i) * 10000, RawNS: w.Start.UnixNano() + int64(i)*10000000, Ordinal: uint64(i + 1), Direction: d, Bytes: length + i%3})
	}
	g.Windows = []Window{w}
	return g
}
func fixtureGroups() []Group {
	out := []Group{}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 4; i++ {
			for _, class := range []string{"benign", "belnet"} {
				length := 100
				if class == "belnet" {
					length = 1200
				}
				out = append(out, fixtureGroup(fmt.Sprintf("%s-%s-%d", split, class, i), split, class, length))
			}
		}
	}
	return out
}
func stump() *traffic.Model {
	return &traffic.Model{SchemaVersion: traffic.SchemaVersion, FeatureNames: traffic.FeatureNames(), Trees: []traffic.Tree{{Nodes: []traffic.Node{{Feature: 16, Threshold: 500, Left: 1, Right: 2}, {Leaf: true, Probability: .1}, {Leaf: true, Probability: .9}}}}}
}
func TestMetadataCannotLeakIntoExistingFeatureVectorOrScore(t *testing.T) {
	g := fixtureGroup("g", "train", "belnet", 1200)
	o := observation(g, g.Windows[0])
	changed := o
	changed.GroupID = "different"
	changed.SessionID = "other"
	changed.Class = "benign"
	changed.Split = "test"
	changed.Profile = "totally-unrelated"
	if len(traffic.Features(o)) != 80 || !reflect.DeepEqual(traffic.Features(o), traffic.Features(changed)) || stump().Score(o) != stump().Score(changed) {
		t.Fatal("provenance entered features")
	}
}
func TestSyntheticTrainingJointCalibrationDeterminismAndRoundTrip(t *testing.T) {
	groups := fixtureGroups()
	f := Freeze{}
	first, err := fitAuxiliary(groups, f, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	second, err := fitAuxiliary(groups, f, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("fixed seed/model not deterministic")
	}
	first.FrozenAt = time.Now().UTC()
	if err = validatePolicy(first); err != nil {
		t.Fatal(err)
	}
	for split, m := range first.Calibration {
		if m.GroupFPR == nil || *m.GroupFPR > .05 || m.FlowFPR == nil || *m.FlowFPR > .05 {
			t.Fatal("joint budget failed", split, m)
		}
	}
	if first.Model == nil || len(first.Model.Trees) != 128 || first.Config.Depth != 8 || first.Threshold != first.Model.Threshold {
		t.Fatal("predeclared model contract changed")
	}
	var round Policy
	raw, _ := json.Marshal(first)
	if err = json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	if err = validatePolicy(round); err != nil {
		t.Fatal(err)
	}
	if first.Model.Score(observation(groups[0], groups[0].Windows[0])) != round.Model.Score(observation(groups[0], groups[0].Windows[0])) {
		t.Fatal("model roundtrip score changed")
	}
}
func TestWholeGroupORCannotHideManyWindowFalsePositives(t *testing.T) {
	groups := []Group{}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 40; i++ {
			g := fixtureGroup(fmt.Sprintf("%s-%d", split, i), split, "benign", 100)
			for j := 0; j < 30; j++ {
				w := g.Windows[0]
				w.ID += fmt.Sprint(j)
				g.Windows = append(g.Windows, w)
			}
			spike := fixtureGroup("spike", split, "benign", 1200).Windows[0]
			spike.FlowID = "tcp0"
			g.Windows = append(g.Windows, spike)
			groups = append(groups, g)
		}
	}
	m := stump()
	threshold, err := jointThreshold(groups, m)
	if err != nil {
		t.Fatal(err)
	}
	if threshold != .9 {
		t.Fatal("per-window calibration leaked groupOR", threshold)
	}
	metrics := measure(evaluate(groups, Policy{Model: m, Threshold: threshold}))
	if metrics.FP != 0 {
		t.Fatal("strict equal-score ties blocked benign", metrics)
	}
}
func TestHighFanoutRequiresDirectFlowBudgetAsWellAsGroupBudget(t *testing.T) {
	groups := []Group{}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 40; i++ {
			g := fixtureGroup(fmt.Sprintf("%s-%d", split, i), split, "benign", 100)
			if i == 0 {
				g.Windows = nil
				for flow := 0; flow < 200; flow++ {
					w := fixtureGroup("fanout", split, "benign", 1200).Windows[0]
					w.FlowID = fmt.Sprint(flow)
					g.Windows = append(g.Windows, w)
				}
			}
			groups = append(groups, g)
		}
	}
	m := stump()
	loose := measure(evaluate(groups, Policy{Model: m, Threshold: .1}))
	if loose.GroupFPR == nil || *loose.GroupFPR > .05 || loose.FlowFPR == nil || *loose.FlowFPR < .8 {
		t.Fatal("fixture did not expose fanout", loose)
	}
	threshold, err := jointThreshold(groups, m)
	if err != nil || threshold != .9 {
		t.Fatal("flow joint threshold omitted", threshold, err)
	}
}
func TestSparseAmbiguousDisabledAndIncompleteAreNotPasses(t *testing.T) {
	g := fixtureGroup("g", "train", "benign", 100)
	p := Policy{Model: stump(), Threshold: .5}
	g.Windows[0].OrderingAmbiguous = true
	g.Windows[0].MaskedRules = []string{"r05", "r06", "r10", "r15"}
	d := evaluate([]Group{g}, p)[0]
	if d.Eligible || d.Detected || d.Status != "auxiliary_INCONCLUSIVE_no_supported_windows" {
		t.Fatal("ambiguous window became scored nondetection", d)
	}
	g.Windows[0].OrderingAmbiguous = false
	g.Windows[0].Events = g.Windows[0].Events[:2]
	d = evaluate([]Group{g}, p)[0]
	if d.Eligible || d.Detected {
		t.Fatal("sparse vector scored")
	}
	g = fixtureGroup("g", "train", "benign", 100)
	p.Disabled = true
	d = evaluate([]Group{g}, p)[0]
	if d.Status != "auxiliary_INCONCLUSIVE_disabled" || d.Detected {
		t.Fatal("disabled classifier called pass")
	}
	g.Complete = false
	d = evaluate([]Group{g}, p)[0]
	if d.Status != "incomplete_UNKNOWN" {
		t.Fatal("incomplete became complete")
	}
}
func TestInsufficientEligibleGroupsProduceExplicitDisabledPolicy(t *testing.T) {
	groups := fixtureGroups()
	for i := range groups {
		groups[i].Windows[0].Events = nil
	}
	p, err := fitAuxiliary(groups, Freeze{}, strings.Repeat("a", 64))
	if err != nil || !p.Disabled || p.Model != nil || p.DisabledReason == "" {
		t.Fatal("unsupported cohort fabricated a forest", err, p.DisabledReason)
	}
}
func TestTestDiagnosticPairedLeakAndCensorRejectedBeforeFitting(t *testing.T) {
	for _, mutate := range []func([]Group){func(g []Group) { g[0].Metadata.Split = "test" }, func(g []Group) { g[0].Metadata.Split = "development" }, func(g []Group) { g[0].Metadata.Scope = "diagnostic" }, func(g []Group) { g[0].Complete = false }, func(g []Group) { g[8].Metadata.SourceWorkloadID = g[0].Metadata.SourceWorkloadID }} {
		groups := fixtureGroups()
		mutate(groups)
		if _, err := fitAuxiliary(groups, Freeze{}, "fixture"); err == nil {
			t.Fatal("invalid cohort entered fitting")
		}
	}
}
func TestInvalidModelAndThresholdCannotLoad(t *testing.T) {
	p, err := fitAuxiliary(fixtureGroups(), Freeze{}, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	p.FrozenAt = time.Now().UTC()
	p.Threshold = math.NaN()
	if validatePolicy(p) == nil {
		t.Fatal("NaN threshold accepted")
	}
}

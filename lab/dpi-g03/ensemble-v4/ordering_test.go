package main

import "testing"

func TestAmbiguityMasksLogicalRulesButPreservesCaptureView(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	w := Window{ID: "w", FlowID: "tcp", Eligible: true, OrderingAmbiguous: true, MaskedRules: []string{"r05", "r06", "r10", "r15"}, Scores: map[string]float64{"r01": .7, "r05": 1, "r10": 1}}
	// Logicaltime metadata is deliberately reversed relative to original capture order.
	for i := 0; i < 16; i++ {
		direction, ordinal := -1, uint64(i+2)
		if i%2 == 1 {
			direction = 1
			ordinal = uint64(i)
		}
		w.Events = append(w.Events, Event{At: int64(10 + i), RawNS: int64(10000 + i*1000), Ordinal: ordinal, Direction: direction, Bytes: 128})
	}
	g.Windows = []Window{w}
	groups := []Group{g}
	applyOrderingMasks(groups)
	addCaptureOrderScores(groups)
	s := groups[0].Windows[0].Scores
	if _, ok := s["r05"]; ok {
		t.Fatal("ambiguous logical alternation retained")
	}
	if _, ok := s["r10"]; ok {
		t.Fatal("invented reply timing retained")
	}
	if s["r01"] != .7 || s[captureOrderRules[0].ID] != 1 || s[captureOrderRules[1].ID] != 1 {
		t.Fatalf("count/capture view was weakened:%v", s)
	}
}
func TestMissingMaskOrDuplicateOrdinalCannotPass(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	g.Windows = []Window{{ID: "w", Eligible: true, OrderingAmbiguous: true}}
	groups := []Group{g}
	applyOrderingMasks(groups)
	if groups[0].Complete || groups[0].Windows[0].Eligible {
		t.Fatal("unbound mask accepted")
	}
}
func TestSourceClusterORDoesNotPretendReplicasIndependent(t *testing.T) {
	d := []Decision{{GroupID: "replica1", SourceWorkloadID: "source", Class: "benign", Split: "test", Complete: true}, {GroupID: "replica2", SourceWorkloadID: "source", Class: "benign", Split: "test", Complete: true, Detected: true}}
	m := sourceClusters(d)["test"]
	if m.Clusters != 1 || m.Benign != 1 || m.FalsePositive != 1 {
		t.Fatalf("cluster OR wrong:%+v", m)
	}
}
func TestVisibleAmbiguityCannotBeHiddenByFalseFlag(t *testing.T) {
	e := []Event{{At: 10, RawNS: 10000, Ordinal: 1, Direction: 1}, {At: 10, RawNS: 10001, Ordinal: 2, Direction: -1}}
	ambiguous, causal := visibleAmbiguity(e)
	if !ambiguous || causal {
		t.Fatal("projected crossdirection tie was lost")
	}
	e = []Event{{At: 11, RawNS: 11000, Ordinal: 1, Direction: 1}, {At: 10, RawNS: 10000, Ordinal: 1, Direction: 1}}
	_, causal = visibleAmbiguity(e)
	if !causal {
		t.Fatal("same-direction reversal was relabelled harmless")
	}
}

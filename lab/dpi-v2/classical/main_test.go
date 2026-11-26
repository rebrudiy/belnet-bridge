package main

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func fixed() []Event {
	e := make([]Event, 64)
	for i := range e {
		d := 1
		if i%2 != 0 {
			d = -1
		}
		e[i] = Event{int64(i) * 10_000, d, 1004}
	}
	return e
}
func diverse(seed int) []Event {
	e := make([]Event, 64)
	at := int64(0)
	for i := range e {
		d := 1
		if (i+seed)%5 < 3 {
			d = -1
		}
		at += int64((i*i*7919+seed*3169)%40000 + 201)
		e[i] = Event{at, d, 32 + (i*977+seed*47)%15000}
	}
	return e
}
func fixture() []Observation {
	obs := []Observation{}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 40; i++ {
			id := fmt.Sprintf("%s-benign-%d", split, i)
			obs = append(obs, Observation{SessionID: id, GroupID: id, Split: split, Class: "benign", Profile: "diverse", Events: diverse(i)})
		}
		for i := 0; i < 6; i++ {
			id := fmt.Sprintf("%s-belnet-%d", split, i)
			obs = append(obs, Observation{SessionID: id, GroupID: id, Split: split, Class: "belnet", Profile: "fixed", Events: fixed()})
		}
	}
	return obs
}

func TestFixedCellSignatures(t *testing.T) {
	e := fixed()
	for _, i := range []int{0, 1, 2, 4, 5, 6, 7, 8, 10, 11, 13, 14} {
		if s := score(i, e); math.Abs(s-1) > 1e-12 {
			t.Errorf("%s: got %f want1", rules[i].ID, s)
		}
	}
	if score(12, e) != 0 {
		t.Fatal("1004-byte cells classified as <=512")
	}
	if score(9, e) != 1 {
		t.Fatal("10ms paired reply boundary wrong")
	}
}
func TestSparseAbstains(t *testing.T) {
	for i := range rules {
		if s := score(i, fixed()[:2]); s != -1 {
			t.Errorf("%s sparse score %f", rules[i].ID, s)
		}
	}
}
func TestTimingChangeDoesNotChangeLengthSignature(t *testing.T) {
	a := fixed()
	b := append([]Event(nil), a...)
	for i := range b {
		b[i].At += int64((i * i * 37) % 1000)
	}
	if !(score(6, b) < score(6, a)) {
		t.Fatal("clock jitter not measured")
	}
	if score(0, a) != score(0, b) {
		t.Fatal("length signature depends on timing")
	}
}
func TestCutoffTiesRespectBudget(t *testing.T) {
	scores := make([]float64, 40)
	for i := range scores {
		scores[i] = float64(i%7) / 7
	}
	threshold := cutoff(append([]float64(nil), scores...), 0.05)
	hits := 0
	for _, s := range scores {
		if s >= threshold {
			hits++
		}
	}
	if hits > 2 {
		t.Fatalf("ties consumed %d positives, budget2", hits)
	}
	if cutoff(nil, .05) != 2 {
		t.Fatal("no calibration controls should fail closed")
	}
}
func TestTestFeaturesNeverInfluenceFit(t *testing.T) {
	obs := fixture()
	before, err := fit(obs, .05)
	if err != nil {
		t.Fatal(err)
	}
	obs = append(obs, Observation{SessionID: "unseen", GroupID: "unseen", Split: "test", Class: "arbitrary ignored test label", Events: []Event{{-5, 999, -8}}})
	after, err := fit(obs, .05)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("test changed frozen policy")
	}
}
func TestCalibrationRejectsGroupLeakage(t *testing.T) {
	obs := fixture()
	obs = append(obs, Observation{SessionID: "test-duplicate-group", GroupID: obs[0].GroupID, Split: "test"})
	if _, err := fit(obs, .05); err == nil {
		t.Fatal("source-group leakage accepted")
	}
}
func TestAllFifteenJointPoliciesRespectCalibrationBudget(t *testing.T) {
	p, err := fit(fixture(), .05)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rounds) != 15 {
		t.Fatal("missing explicit rounds")
	}
	for _, r := range p.Rounds {
		if len(r.Rules) != r.Number {
			t.Fatal("round failed to add exactly one rule")
		}
		for split, m := range r.Calibration {
			if m.FPR == nil || m.GroupFPR == nil || *m.FPR > .05 || *m.GroupFPR > .05 {
				t.Fatalf("round%d %s exceeded calibrated flow/group budget: %+v", r.Number, split, m)
			}
		}
	}
	if _, err := json.Marshal(p); err != nil {
		t.Fatal("nonfinite threshold serialization", err)
	}
}
func TestLateWindowBoundariesAndOwnership(t *testing.T) {
	o := Observation{Events: []Event{{0, 1, 32}, {4_999_999, -1, 33}, {5_000_000, 1, 34}, {6_999_999, -1, 35}, {7_000_000, 1, 36}}}
	got := events(o, 5_000_000)
	want := []Event{{0, 1, 34}, {1_999_999, -1, 35}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("late window: %+v", got)
	}
	got[0].Bytes = 999
	if o.Events[2].Bytes != 34 {
		t.Fatal("window mutated input")
	}
	o.Offset = 5_000_000
	o.Events = want
	if !reflect.DeepEqual(events(o, 5_000_000), want) {
		t.Fatal("pre-extracted late windows double-shifted")
	}
	if len(events(o, 0)) != 0 {
		t.Fatal("late-only source treated as handshake prefix")
	}
}
func TestGroupFPRCountsAnyFlowHit(t *testing.T) {
	obs := fixture()
	for i := 1; i < 5; i++ {
		obs[i].GroupID = obs[0].GroupID
	}
	m := measure(obs, []RulePolicy{{Rule: rules[0], Threshold: 0, Enabled: true}}, 0, 0)
	if m.FPBenignGroups != m.BenignGroups {
		t.Fatal("group OR missed false positives")
	}
}
func TestMalformedObservationsRejected(t *testing.T) {
	for _, e := range []Event{{-1, 1, 32}, {0, 0, 32}, {0, 1, 4}, {0, -1, 65541}} {
		o := Observation{SessionID: "a", GroupID: "a", Class: "benign", Split: "train", Events: []Event{e}}
		if validate([]Observation{o}) == nil {
			t.Fatalf("invalid event accepted %+v", e)
		}
	}
}

func TestRulePrefixesAndPolicyValidation(t *testing.T) {
	for _, n := range []int{1, 7, 15} {
		p, err := fit(fixture(), .05, n)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Rules) != n || len(p.Rounds) != n {
			t.Fatalf("prefix%d expanded", n)
		}
		if err := validatePolicy(p); err != nil {
			t.Fatal(err)
		}
		p.Rounds[0].Rules = nil
		if validatePolicy(p) == nil {
			t.Fatal("malformed policy accepted")
		}
	}
	for _, n := range []int{0, 16} {
		if _, err := fit(fixture(), .05, n); err == nil {
			t.Fatal("bad rule count accepted")
		}
	}
}

// Exact reproducibility is necessary when calibration puts a threshold one ULP
// above a tied score. Unordered floating-point entropy sums violate that contract.
func TestEntropyBitwiseDeterministic(t *testing.T) {
	for categories := 3; categories <= 31; categories++ {
		events := []Event{}
		for i := 0; i < 64; i++ {
			bucket := ((i*i + i*11) % 37) % categories
			events = append(events, Event{int64(i) * 1000, 1, 100 + bucket*97})
		}
		first := math.Float64bits(score(3, events))
		for attempt := 0; attempt < 1000; attempt++ {
			if got := math.Float64bits(score(3, events)); got != first {
				t.Fatalf("identical events produced differing entropy scores: categories%d bits %x vs %x (attempt%d)", categories, first, got, attempt)
			}
		}
	}
}

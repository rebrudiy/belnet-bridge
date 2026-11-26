package main

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestOppositeDirectionRecordReversalIsMaskedNotCausalFailure(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_004_000, tcp(-1, 401, 24, record(21)))
	f.packet(1_000_000, tcp(1, 101, 24, record(21)))
	m := metadata()
	m.MeasurementStartMicros = epochNS / 1000
	got := f.read(t, m)
	w := findWindow(t, got.Flows[0], "flow-prefix")
	if !got.CoverageComplete || got.ClockDiagnostics.RecordCausalBackwardEdges != 0 || got.ClockDiagnostics.CrossDirectionRecordBackwards != 1 || got.ClockDiagnostics.PerStreamBackwardEdges != 0 {
		t.Fatal("independent directions became causal failure", got.ClockDiagnostics)
	}
	if w.Start.UnixNano() != epochNS+1_000_000 || len(w.Events) != 2 || w.Events[0].Ordinal != 2 || w.Events[0].At != 0 || w.Events[1].At != 4 {
		t.Fatal("true minimum prefix/raw metadata merge failed", w)
	}
	if !w.OrderingAmbiguous || !reflect.DeepEqual(w.MaskedRules, orderSensitiveRules) {
		t.Fatal("order-sensitive rules unmasked", w.MaskedRules)
	}
}
func TestEqualRawAndProjectedTimestampTiesAreMasked(t *testing.T) {
	for _, delta := range []int64{0, 800} {
		f := newFixture(true)
		f.syn()
		f.packet(1_000_100, tcp(1, 101, 24, record(21)))
		f.packet(1_000_100+delta, tcp(-1, 401, 24, record(21)))
		got := f.read(t, metadata())
		w := findWindow(t, got.Flows[0], "flow-prefix")
		if !got.CoverageComplete || !w.OrderingAmbiguous || !contains(w.AmbiguityReasons, "opposite_direction_equal_at_micros") {
			t.Fatal("unverifiable projected tie got a direction order", delta, w)
		}
		if delta == 0 && !contains(w.AmbiguityReasons, "opposite_direction_equal_raw_ns") {
			t.Fatal("raw tie missing")
		}
	}
}
func TestBoundedEarliest64AcrossReorderedDirections(t *testing.T) {
	f := newFixture(true)
	f.syn()
	ordinal := uint64(0)
	all := []Event{}
	seq := map[int]uint32{1: 101, -1: 401}
	for _, d := range []int{1, -1} {
		for i := 0; i < 64; i++ {
			at := int64(100+i) * int64(time.Millisecond)
			if d == -1 {
				at = int64(50+i) * int64(time.Millisecond)
			}
			r := record(21)
			f.packet(at, tcp(d, seq[d], 24, r))
			seq[d] += uint32(len(r))
			ordinal++
			all = append(all, Event{RawNS: epochNS + at, Ordinal: ordinal, Direction: d, Bytes: 26})
		}
	}
	got := f.read(t, metadata())
	w := findWindow(t, got.Flows[0], "flow-prefix")
	sort.Slice(all, func(i, j int) bool { return eventLess(all[i], all[j]) })
	if !got.CoverageComplete || w.TotalRecords != 128 || len(w.Events) != 64 || !w.SelectionTruncated {
		t.Fatal("bounded selection/counters failed")
	}
	for i, e := range w.Events {
		if e.RawNS != all[i].RawNS || e.Ordinal != all[i].Ordinal {
			t.Fatal("selected first file records instead of earliest timestamps", i)
		}
	}
	if !w.OrderingAmbiguous || !reflect.DeepEqual(w.MaskedRules, orderSensitiveRules) {
		t.Fatal("reordered selection had no mask")
	}
}
func TestSameDirectionTimestampTieIsNotAmbiguous(t *testing.T) {
	f := newFixture(true)
	f.syn()
	a, b := record(21), record(22)
	f.packet(1_000_000, tcp(1, 101, 24, append(a, b...)))
	got := f.read(t, metadata())
	w := findWindow(t, got.Flows[0], "flow-prefix")
	if w.OrderingAmbiguous || len(w.MaskedRules) != 0 || len(w.Events) != 2 || w.Events[0].Ordinal >= w.Events[1].Ordinal {
		t.Fatal("TCP-known same-direction order lost")
	}
}

func TestOppositeDirectionTieBeyond64StillMasksWholeWindow(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := uint32(101)
	for i := 0; i < 64; i++ {
		r := record(21)
		f.packet(1_000_000, tcp(1, seq, 24, r))
		seq += uint32(len(r))
	}
	f.packet(1_000_000, tcp(-1, 401, 24, record(21)))
	got := f.read(t, metadata())
	w := findWindow(t, got.Flows[0], "flow-prefix")
	if len(w.Events) != 64 || w.TotalRecords != 65 || !w.OrderingAmbiguous || !contains(w.AmbiguityReasons, "opposite_direction_equal_raw_ns") {
		t.Fatal("postselection tie silently hidden", w)
	}
}

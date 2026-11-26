package main

import "sort"

type rawRecordIdentity struct {
	NS               int64
	Direction, Bytes int
	FlowID           string
}

func compatibleOptional(frozen, reported Assignment) bool {
	return (reported.SourceWorkloadID == "" || reported.SourceWorkloadID == frozen.SourceWorkloadID) && (reported.Scope == "" || reported.Scope == frozen.Scope) && (reported.Transport == "" || reported.Transport == frozen.Transport) && (reported.ClientStack == "" || reported.ClientStack == frozen.ClientStack)
}

func visibleAmbiguity(events []Event) (ambiguous bool, causalViolation bool) {
	e := append([]Event(nil), events...)
	sort.Slice(e, func(i, j int) bool { return e[i].Ordinal < e[j].Ordinal })
	type last struct {
		set    bool
		ns, at int64
	}
	directions := map[int]last{}
	for i, v := range e {
		if v.Ordinal == 0 {
			return true, true
		}
		if i > 0 && v.Ordinal == e[i-1].Ordinal {
			return true, true
		}
		own := directions[v.Direction]
		if own.set && v.RawNS < own.ns {
			causalViolation = true
		}
		opposite := directions[-v.Direction]
		if opposite.set && (v.RawNS <= opposite.ns || v.At <= opposite.at) {
			ambiguous = true
		}
		directions[v.Direction] = last{true, v.RawNS, v.At}
	}
	return ambiguous, causalViolation
}

func validOrderingMask(w Window) bool {
	want := []string{"r05", "r06", "r10", "r15"}
	got := append([]string{}, w.MaskedRules...)
	sort.Strings(got)
	if !w.OrderingAmbiguous {
		return len(got) == 0
	}
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

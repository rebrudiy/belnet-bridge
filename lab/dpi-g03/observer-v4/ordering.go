package main

import "sort"

const OrderingSemanticsSHA = "a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1"

var orderSensitiveRules = []string{"r05", "r06", "r10", "r15"}

func eventLess(a, b Event) bool {
	if a.RawNS != b.RawNS {
		return a.RawNS < b.RawNS
	}
	return a.Ordinal < b.Ordinal
}
func selectEarliest(w *Window, e Event) bool {
	index := sort.Search(len(w.Events), func(i int) bool { return eventLess(e, w.Events[i]) })
	if len(w.Events) >= MaxSelected && index == len(w.Events) {
		return false
	}
	grew := len(w.Events) < MaxSelected
	if grew {
		w.Events = append(w.Events, Event{})
	}
	copy(w.Events[index+1:], w.Events[index:])
	w.Events[index] = e
	return grew
}
func annotateOrdering(w *Window) {
	reasons := append([]string{}, w.AmbiguityReasons...)
	add := func(r string) { addReason(&reasons, r) }
	ordered := append([]Event{}, w.Events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Ordinal < ordered[j].Ordinal })
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Direction != ordered[i-1].Direction && ordered[i].RawNS < ordered[i-1].RawNS {
			add("opposite_direction_record_file_time_reversal")
		}
	}
	for _, projected := range []bool{false, true} {
		masks := map[int64]int{}
		for _, e := range w.Events {
			key := e.RawNS
			if projected {
				key = e.At
			}
			bit := 1
			if e.Direction == -1 {
				bit = 2
			}
			masks[key] |= bit
		}
		for _, m := range masks {
			if m == 3 {
				if projected {
					add("opposite_direction_equal_at_micros")
				} else {
					add("opposite_direction_equal_raw_ns")
				}
				break
			}
		}
	}
	sort.Strings(reasons)
	w.AmbiguityReasons = reasons
	w.OrderingAmbiguous = len(reasons) > 0
	w.MaskedRules = []string{}
	if w.OrderingAmbiguous {
		w.MaskedRules = append(w.MaskedRules, orderSensitiveRules...)
	}
}

func observeOrdering(w *Window, e Event) {
	index, other := 0, 1
	if e.Direction == -1 {
		index, other = 1, 0
	}
	if w.orderHave[other] {
		prior := w.orderLast[other]
		if e.RawNS < prior {
			addReason(&w.AmbiguityReasons, "opposite_direction_record_file_time_reversal")
		}
		if e.RawNS == prior {
			addReason(&w.AmbiguityReasons, "opposite_direction_equal_raw_ns")
		}
		if e.At == (prior-w.start)/1000 {
			addReason(&w.AmbiguityReasons, "opposite_direction_equal_at_micros")
		}
	}
	w.orderHave[index] = true
	w.orderLast[index] = e.RawNS
}

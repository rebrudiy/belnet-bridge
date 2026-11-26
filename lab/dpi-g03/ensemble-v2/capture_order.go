package main

import "sort"

var captureOrderRules = []Rule{
	{ID: "co01_capture_order_alternation", Name: "Capture-order direction alternation", Definition: "Among canonical earliest64 UTC-selected metadata records, order by original unique completion ordinal; direction changes/adjacent pairs, >=16 records. Sensor-conditioned arrival view; no claim of physical/time ordering."},
	{ID: "co02_capture_order_equal_neighbors", Name: "Capture-order equal opposite neighbors", Definition: "Among same UTC-selected metadata records sorted by original completion ordinal, adjacent opposite-direction equal-length pairs/adjacent pairs, >=16 records; no time comparison or invented timestamps."},
}

func addCaptureOrderScores(groups []Group) {
	for i := range groups {
		for j := range groups[i].Windows {
			w := &groups[i].Windows[j]
			if !w.Eligible || len(w.Events) < 16 {
				continue
			}
			e := append([]Event(nil), w.Events...)
			sort.Slice(e, func(i, j int) bool { return e[i].Ordinal < e[j].Ordinal })
			valid := true
			changes, equal := 0, 0
			for k := 1; k < len(e); k++ {
				if e[k].Ordinal == e[k-1].Ordinal {
					valid = false
					break
				}
				if e[k].Direction != e[k-1].Direction {
					changes++
					if e[k].Bytes == e[k-1].Bytes {
						equal++
					}
				}
			}
			if !valid {
				addCoverage(&groups[i], "duplicate_raw_ordinal_capture_view")
				w.Eligible = false
				continue
			}
			if w.Scores == nil {
				w.Scores = map[string]float64{}
			}
			w.Scores[captureOrderRules[0].ID] = float64(changes) / float64(len(e)-1)
			w.Scores[captureOrderRules[1].ID] = float64(equal) / float64(len(e)-1)
		}
	}
}

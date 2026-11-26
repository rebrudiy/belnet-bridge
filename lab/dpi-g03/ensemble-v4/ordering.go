package main

import (
	"fmt"
	"sort"
)

type rawRecordIdentity struct {
	NS               int64
	Direction, Bytes int
	FlowID           string
}

func compatibleOptional(frozen, reported Assignment) bool {
	return (reported.SourceWorkloadID == "" || reported.SourceWorkloadID == frozen.SourceWorkloadID) && (reported.Scope == "" || reported.Scope == frozen.Scope) && (reported.Transport == "" || reported.Transport == frozen.Transport) && (reported.ClientStack == "" || reported.ClientStack == frozen.ClientStack)
}

var ambiguityRules = []string{"r05", "r06", "r10", "r15"}

// Counts and within-direction timing remain usable; cross-direction adjacency
// never gets an invented order from canonical event serialization.
func applyOrderingMasks(groups []Group) {
	for i := range groups {
		g := &groups[i]
		for j := range g.Windows {
			w := &g.Windows[j]
			visible, causal := visibleAmbiguity(w.Events)
			if causal || visible && !w.OrderingAmbiguous {
				addCoverage(g, "unreported_ordering_or_causal_violation:"+w.ID)
				w.Eligible = false
			}
			if !w.OrderingAmbiguous {
				if len(w.MaskedRules) > 0 {
					addCoverage(g, "unexpected_ordering_mask:"+w.ID)
					w.Eligible = false
				}
				continue
			}
			expected := append([]string(nil), ambiguityRules...)
			actual := append([]string(nil), w.MaskedRules...)
			sort.Strings(expected)
			sort.Strings(actual)
			if fmt.Sprint(expected) != fmt.Sprint(actual) {
				addCoverage(g, "ordering_mask_mismatch:"+w.ID)
				w.Eligible = false
			}
			for _, id := range ambiguityRules {
				if w.Abstentions == nil {
					w.Abstentions = map[string][]string{}
				}
				w.Abstentions[id] = []string{"ambiguous_bidirectional_order"}
				delete(w.Scores, id)
			}
		}
	}
}

type ClusterMetrics struct {
	Clusters      int      `json:"source_class_clusters"`
	Benign        int      `json:"benign_clusters"`
	FalsePositive int      `json:"detected_benign_clusters"`
	Positive      int      `json:"positive_clusters"`
	TruePositive  int      `json:"detected_positive_clusters"`
	Complete      int      `json:"complete_clusters"`
	Incomplete    int      `json:"incomplete_clusters"`
	FPR           *float64 `json:"observed_cluster_fpr"`
	TPR           *float64 `json:"observed_cluster_tpr"`
	Scope         string   `json:"scope"`
}

func sourceClusters(ds []Decision) map[string]ClusterMetrics {
	type state struct {
		split, class       string
		detected, complete bool
	}
	clusters := map[string]state{}
	for _, d := range ds {
		key := d.Split + "|" + d.Class + "|" + d.SourceWorkloadID
		c, ok := clusters[key]
		if !ok {
			c = state{split: d.Split, class: d.Class, complete: true}
		}
		c.detected = c.detected || d.Detected
		c.complete = c.complete && d.Complete
		clusters[key] = c
	}
	result := map[string]ClusterMetrics{}
	for _, c := range clusters {
		m := result[c.split]
		m.Scope = "Descriptive OR within same split,class,source_workload_id. Source metadata is not a classifier feature; clusters also share origins/stacks and are not proven IID."
		m.Clusters++
		if c.complete {
			m.Complete++
		} else {
			m.Incomplete++
		}
		if c.class == "benign" {
			m.Benign++
			if c.detected {
				m.FalsePositive++
			}
		} else {
			m.Positive++
			if c.detected {
				m.TruePositive++
			}
		}
		result[c.split] = m
	}
	for split, m := range result {
		m.FPR = ratio(m.FalsePositive, m.Benign)
		m.TPR = ratio(m.TruePositive, m.Positive)
		result[split] = m
	}
	return result
}

// Visible selected records provide a lower bound on ambiguity: an observer may
// additionally flag omitted records, but cannot hide ambiguity visible here.
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

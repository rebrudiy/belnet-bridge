package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const ConservativeAnalysis = "r4-worst-case-benign-fp-v1"

type InconclusiveError struct{ Reason string }

func (e *InconclusiveError) Error() string {
	return "INCONCLUSIVE: " + e.Reason + "; no certified policy"
}

func addAffectedFlow(g *Group, id string) {
	found := false
	for _, known := range g.PrimaryFlowIDs {
		if known == id {
			found = true
		}
	}
	if !found {
		g.UncertaintyBounded = false
		return
	}
	for _, known := range g.AffectedFlowIDs {
		if known == id {
			return
		}
	}
	g.AffectedFlowIDs = append(g.AffectedFlowIDs, id)
	sort.Strings(g.AffectedFlowIDs)
}

// This never upgrades coverage. A local semantic fault can have a bounded
// affected-flow set; an unverified census/metadata/capture cannot be certified.
func setUncertainty(g *Group, c Capture) {
	g.UncertaintyBounded = false
	g.AffectedFlowIDs = nil
	if g.Complete {
		g.UncertaintyBounded = true
		return
	}
	ids := map[string]bool{}
	for _, id := range g.PrimaryFlowIDs {
		ids[id] = true
	}
	if len(ids) == 0 {
		return
	}
	unknown := map[string]bool{}
	for _, reason := range c.GlobalReasons {
		if !strings.HasPrefix(reason, "primary_flow_fault: ") {
			g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
			return
		}
		fault := strings.TrimPrefix(reason, "primary_flow_fault: ")
		mapped := false
		for _, flow := range c.Flows {
			if !ids[flow.ID] {
				continue
			}
			for _, issue := range flow.Issues {
				if issue == fault {
					unknown[flow.ID] = true
					mapped = true
				}
			}
		}
		if !mapped {
			g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
			return
		}
	}
	if len(unknown) == 0 {
		g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
		return
	}
	for _, w := range c.GroupWindows {
		if w.Eligible {
			continue
		}
		if len(w.Reasons) == 0 {
			g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
			return
		}
		for _, reason := range w.Reasons {
			mapped := false
			for _, global := range c.GlobalReasons {
				if global == "primary_flow_fault: "+reason {
					mapped = true
				}
			}
			if !mapped {
				g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
				return
			}
		}
	}
	for _, w := range c.Windows {
		if !ids[w.FlowID] || !w.Primary || w.Status == "not_applicable" || w.Eligible {
			continue
		}
		if len(w.Reasons) == 0 {
			g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
			return
		}
		for _, reason := range w.Reasons {
			mapped := false
			for _, global := range c.GlobalReasons {
				if global == "primary_flow_fault: "+reason {
					mapped = true
				}
			}
			if !mapped {
				g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
				return
			}
		}
		unknown[w.FlowID] = true
	}
	for _, reason := range g.Reasons {
		if strings.HasPrefix(reason, "primary_flow_fault: ") {
			continue
		}
		switch reason {
		case "observer_coverage_incomplete", "incomplete_declared_group_window", "incomplete_flow_or_reconnect_window":
		default:
			g.AffectedFlowIDs = append([]string(nil), g.PrimaryFlowIDs...)
			return
		}
	}
	for id := range unknown {
		g.AffectedFlowIDs = append(g.AffectedFlowIDs, id)
	}
	sort.Strings(g.AffectedFlowIDs)
	g.UncertaintyBounded = true
}

func worstGroupValue(g Group, value float64) float64 {
	if g.Metadata.Class == "benign" && !g.Complete {
		return math.Inf(1)
	}
	return value
}
func worstFlowValues(g Group, scorer func(Window) float64) []float64 {
	values := map[string]float64{}
	for _, id := range g.PrimaryFlowIDs {
		values[id] = -2
	}
	for _, w := range g.Windows {
		if !w.Eligible {
			continue
		}
		if old, ok := values[w.FlowID]; !ok || scorer(w) > old {
			values[w.FlowID] = scorer(w)
		}
	}
	if g.Metadata.Class == "benign" && !g.Complete {
		for _, id := range g.AffectedFlowIDs {
			values[id] = math.Inf(1)
		}
	}
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]float64, 0, len(ids))
	for _, id := range ids {
		out = append(out, values[id])
	}
	return out
}

func uncertaintyFloor(groups []Group, budget float64) error {
	for _, split := range []string{"train", "validation"} {
		total, unknown, flows := 0, 0, 0
		affected := 0
		for _, g := range groups {
			if g.Metadata.Class != "benign" || g.Metadata.Split != split {
				continue
			}
			total++
			flows += len(flowValues(g, func(Window) float64 { return 0 }))
			if !g.Complete {
				unknown++
				if !g.UncertaintyBounded {
					return &InconclusiveError{fmt.Sprintf("%s benign inventory/uncertainty scope unbounded for %s", split, g.Metadata.GroupID)}
				}
				seen := map[string]bool{}
				for _, id := range g.AffectedFlowIDs {
					seen[id] = true
				}
				affected += len(seen)
			}
		}
		if total == 0 || flows == 0 {
			return &InconclusiveError{"benign calibration population missing"}
		}
		if float64(unknown)/float64(total) > budget || float64(affected)/float64(flows) > budget {
			return &InconclusiveError{fmt.Sprintf("%s uncertainty floor groups%d/%d,flows%d/%d exceeds%.2f", split, unknown, total, affected, flows, budget)}
		}
	}
	return nil
}

func worstMetrics(ds []Decision, m *Calibration) {
	unknownGroups, unknownFlows, hitFlows := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range ds {
		if d.Class != "benign" {
			continue
		}
		if !d.Complete {
			unknownGroups[d.GroupID] = true
			if !d.UncertaintyBounded {
				m.UnboundedBenign++
			}
			for _, id := range d.AffectedFlowIDs {
				unknownFlows[d.GroupID+"/"+id] = true
			}
		}
		if d.Detected {
			unknownGroups[d.GroupID] = true
		}
		for _, w := range d.Windows {
			if len(w.Hits) > 0 {
				hitFlows[d.GroupID+"/"+w.FlowID] = true
			}
		}
	}
	for id := range hitFlows {
		unknownFlows[id] = true
	}
	m.WorstFP = len(unknownGroups)
	m.WorstFPR = ratio(m.WorstFP, m.Benign)
	m.WorstFPFlows = len(unknownFlows)
	if m.UnboundedBenign == 0 {
		m.WorstFlowFPR = ratio(m.WorstFPFlows, m.BenignFlows)
	}
	for _, d := range ds {
		if d.Class == "benign" && !d.Complete {
			m.UnknownBenignGroups++
		}
	}
}

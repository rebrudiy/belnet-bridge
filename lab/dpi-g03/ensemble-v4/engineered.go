package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

// These are explicit engineer-authored classical predicates, not fitted model
// weights. Each recipe is committed before its fresh wrapper experiment.
type EngineeredRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Hypothesis  string        `json:"hypothesis"`
	EvidenceSHA string        `json:"development_evidence_sha256"`
	Terms       []FeatureTerm `json:"terms"`
}
type FeatureTerm struct {
	Source string  `json:"source"`
	Shape  string  `json:"shape"`
	Lower  float64 `json:"lower"`
	Upper  float64 `json:"upper"`
}

func engineeredCatalog(base Catalog, recipes []EngineeredRule) (Catalog, error) {
	if len(recipes) == 0 {
		return base, nil
	}
	if len(recipes) > 15 {
		return Catalog{}, fmt.Errorf("at most15 explicit adaptive rules")
	}
	sources := map[string]bool{}
	for _, r := range base.Rules {
		sources[r.ID] = true
	}
	for i, r := range recipes {
		if r.ID != fmt.Sprintf("a%02d", i+1) || r.Name == "" || r.Hypothesis == "" || !hexSHA(r.EvidenceSHA) || len(r.Terms) < 2 || len(r.Terms) > 4 {
			return Catalog{}, fmt.Errorf("sequential named adaptive rule, evidenceSHA and2..4 terms required")
		}
		seen := map[string]bool{}
		for _, t := range r.Terms {
			if !sources[t.Source] || seen[t.Source] || math.IsNaN(t.Lower) || math.IsNaN(t.Upper) || math.IsInf(t.Lower, 0) || math.IsInf(t.Upper, 0) || t.Lower < 0 || t.Upper > 1 || t.Lower >= t.Upper || (t.Shape != "high" && t.Shape != "low" && t.Shape != "band") {
				return Catalog{}, fmt.Errorf("invalid explicit feature membership term for%s", r.ID)
			}
			seen[t.Source] = true
		}
		wire, _ := json.Marshal(r)
		base.Rules = append(base.Rules, Rule{ID: r.ID, Name: r.Name, Definition: "Within one actual TCP flow over the declared primary horizon, independently MAX each available base feature across its eligible windows. AND is minimum of all2..4 explicit memberships; missing/masked input abstains. high=clip((x-lower)/(upper-lower)); low=1-high; band=1 inside[lower,upper],0 outside. Recipe:" + string(wire), Response: r.Hypothesis})
	}
	wire, err := json.Marshal(struct {
		Version string
		BaseSHA string
		Recipes []EngineeredRule
	}{"g03-explicit-membership-v1", base.SHA, recipes})
	if err != nil {
		return Catalog{}, err
	}
	base.SHA = sha(wire)
	return base, nil
}

func membership(t FeatureTerm, value float64) float64 {
	if t.Shape == "band" {
		if value >= t.Lower && value <= t.Upper {
			return 1
		}
		return 0
	}
	v := math.Max(0, math.Min(1, (value-t.Lower)/(t.Upper-t.Lower)))
	if t.Shape == "low" {
		return 1 - v
	}
	return v
}

func addEngineeredScores(groups []Group, recipes []EngineeredRule) {
	if len(recipes) == 0 {
		return
	}
	for i := range groups {
		g := &groups[i]
		features := map[string]map[string]float64{}
		for _, w := range g.Windows {
			if !w.Eligible {
				continue
			}
			if features[w.FlowID] == nil {
				features[w.FlowID] = map[string]float64{}
			}
			for k, v := range w.Scores {
				if old, ok := features[w.FlowID][k]; !ok || v > old {
					features[w.FlowID][k] = v
				}
			}
		}
		ids := append([]string(nil), g.PrimaryFlowIDs...)
		sort.Strings(ids)
		for _, id := range ids {
			w := Window{ID: g.Metadata.GroupID + "/" + id + "/engineered", GroupID: g.Metadata.GroupID, FlowID: id, Kind: "engineered-flow", Split: g.Metadata.Split, Class: g.Metadata.Class, Profile: g.Metadata.Profile, Primary: true, Eligible: true, Status: "complete", Scores: map[string]float64{}, Abstentions: map[string][]string{}}
			w.Start = time.UnixMicro(g.Metadata.MeasurementStartMicros).UTC()
			w.End = w.Start.Add(80 * time.Second)
			for _, recipe := range recipes {
				score, ok := 1.0, true
				for _, term := range recipe.Terms {
					value, present := features[id][term.Source]
					if !present {
						ok = false
						w.Abstentions[recipe.ID] = append(w.Abstentions[recipe.ID], "missing_or_masked_source:"+term.Source)
						continue
					}
					score = math.Min(score, membership(term, value))
				}
				if ok {
					w.Scores[recipe.ID] = score
				}
			}
			if len(w.Scores) > 0 {
				g.Windows = append(g.Windows, w)
			} else {
				w.Eligible = false
				w.Status = "no_engineered_evidence_abstain"
				g.Diagnostics = append(g.Diagnostics, w)
			}
		}
	}
}

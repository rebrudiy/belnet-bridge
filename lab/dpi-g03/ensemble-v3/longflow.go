package main

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"time"
)

const longDefinitionsSHA = "9d866dd631df3601630ee0f3ce0c00383f50a46194bca44cd88349bffade864e"

var longRules = []Rule{
	{ID: "lf01_exact26_share", Name: "Exact26 byte TLS23 record share", Definition: "records with full TLS record length26/all TLS23 records; >=16 records"},
	{ID: "lf02_tiny_le64_share", Name: "Tiny TLS23 record share", Definition: "records with full TLS record length<=64/all TLS23 records; >=16 records"},
	{ID: "lf03_length_concentration", Name: "Whole-flow length concentration", Definition: "1-Shannon(length)/log2(N); >=16 records; exact histogram"},
	{ID: "lf04_duplex_byte_balance", Name: "Whole-flow directional byte balance", Definition: "1-abs(upBytes-downBytes)/(upBytes+downBytes); >=16 records, >=4 eachdirection"},
	{ID: "lf05_immediate_reply_share", Name: "Whole-flow adjacent reply share", Definition: "up immediately followed bydown in0..10ms/upN; >=16 records, >=8 up; no negative adjacency"},
	{ID: "lf06_directional_regularity", Name: "Whole-flow directional regularity", Definition: "max eligible direction1/(1+CVpositive gaps); >=8gaps and200ms span; within actual TCP flow only"},
}

func combinedCatalog(window Catalog, longSHA string) (Catalog, error) {
	return combinedCatalogOrdered(window, longSHA, "")
}
func combinedCatalogOrdered(window Catalog, longSHA, orderingSHA string) (Catalog, error) {
	return combinedCatalogCoverage(window, longSHA, orderingSHA, "5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810")
}
func combinedCatalogCoverage(window Catalog, longSHA string, orderingSHA string, coverageSHA string) (Catalog, error) {
	if len(window.Rules) != 15 || longSHA != longDefinitionsSHA {
		return Catalog{}, fmt.Errorf("exact15+6 feature definitions required")
	}
	c := Catalog{Rules: append(append(append([]Rule(nil), window.Rules...), longRules...), captureOrderRules...)}
	for i := range c.Rules {
		for _, id := range []string{"r05", "r06", "r10", "r15", "lf05_immediate_reply_share"} {
			if c.Rules[i].ID == id {
				c.Rules[i].Definition += "; abstains when cross-direction ordering is ambiguous under " + orderingSHA
			}
		}
	}
	bytes, err := json.Marshal(struct {
		Version     string `json:"version"`
		WindowSHA   string `json:"window_sha256"`
		LongSHA     string `json:"long_sha256"`
		OrderingSHA string `json:"ordering_semantics_sha256"`
		CoverageSHA string `json:"coverage_semantics_sha256"`
		Rules       []Rule `json:"rules"`
	}{DefenderVersion, window.SHA, longSHA, orderingSHA, coverageSHA, c.Rules})
	if err != nil {
		return Catalog{}, err
	}
	c.SHA = sha(bytes)
	return c, nil
}

type LongFeature struct {
	Value    *float64 `json:"value"`
	Eligible bool     `json:"eligible"`
	Support  uint64   `json:"support"`
	Reasons  []string `json:"reasons"`
}
type LongFlow struct {
	OrderingAmbiguous bool                   `json:"ordering_ambiguous"`
	MaskedFeatures    []string               `json:"masked_features"`
	ID                string                 `json:"flow_id"`
	Applicable        bool                   `json:"applicable_to_primary"`
	Eligible          bool                   `json:"coverage_eligible"`
	Reasons           []string               `json:"coverage_reasons"`
	Features          map[string]LongFeature `json:"features"`
}
type LongReport struct {
	CoverageSHA    string     `json:"coverage_semantics_sha256"`
	OrderingSHA    string     `json:"ordering_semantics_sha256"`
	Schema         int        `json:"schema"`
	Version        string     `json:"version"`
	DefinitionsSHA string     `json:"feature_definitions_sha256"`
	PCAPSHA        string     `json:"pcap_sha256"`
	Metadata       Metadata   `json:"metadata"`
	Flows          []LongFlow `json:"flows"`
}

func appendLongReport(g *Group, r LongReport, f Freeze) error {
	if r.Schema != 3 || r.Version != "g03-longflow-v4" || r.CoverageSHA != f.CoverageSHA || r.CoverageSHA != g.CoverageSHA || r.OrderingSHA != f.OrderingSHA || r.OrderingSHA != g.OrderingSHA || r.DefinitionsSHA != f.LongflowDefinitionsSHA || r.PCAPSHA != g.PCAPSHA || (!sameCore(g.Metadata.Assignment, r.Metadata.Assignment) || !compatibleOptional(g.Metadata.Assignment, r.Metadata.Assignment)) || r.Metadata.MeasurementStartMicros != g.Metadata.MeasurementStartMicros || r.Metadata.MeasuredSeconds != 80 || r.Metadata.FreezeSHA != g.Metadata.FreezeSHA {
		return fmt.Errorf("longflow provenance/primary horizon mismatch for%s", g.Metadata.GroupID)
	}
	known := map[string]bool{}
	for _, w := range g.Windows {
		known[w.FlowID] = true
	}
	seen := map[string]bool{}
	for _, lf := range r.Flows {
		if !lf.Applicable {
			if known[lf.ID] {
				if g.PrimaryTLSFlows[lf.ID] {
					return fmt.Errorf("primary TLS flow declared inapplicable")
				}
				if seen[lf.ID] {
					return fmt.Errorf("duplicate inapplicable TCP flow")
				}
				seen[lf.ID] = true

			}
			continue
		}
		if lf.OrderingAmbiguous {
			if len(lf.MaskedFeatures) != 1 || lf.MaskedFeatures[0] != "lf05_immediate_reply_share" {
				return fmt.Errorf("longflow ambiguity mask mismatch")
			}
		} else if len(lf.MaskedFeatures) != 0 {
			return fmt.Errorf("unexpected longflow mask")
		}
		if !known[lf.ID] || seen[lf.ID] {
			return fmt.Errorf("longflow unknown/duplicate actual flow%s", lf.ID)
		}
		seen[lf.ID] = true
		if !g.PrimaryTLSFlows[lf.ID] {
			return fmt.Errorf("longflow active features on observer no-primary-TLS flow")
		}
		for _, sourceWindow := range g.Windows {
			if sourceWindow.FlowID == lf.ID && sourceWindow.OrderingAmbiguous && !sourceWindow.Start.Before(time.UnixMicro(g.Metadata.MeasurementStartMicros)) && !sourceWindow.End.After(time.UnixMicro(g.Metadata.MeasurementStartMicros).Add(80*time.Second)) && !lf.OrderingAmbiguous {
				return fmt.Errorf("longflow ambiguity contradicts observed primary window")
			}
		}
		start := time.UnixMicro(g.Metadata.MeasurementStartMicros).UTC()
		w := Window{ID: g.Metadata.GroupID + "/" + lf.ID + "/whole80", GroupID: g.Metadata.GroupID, Split: g.Metadata.Split, Class: g.Metadata.Class, Profile: g.Metadata.Profile, FlowID: lf.ID, Kind: "whole-flow80", Start: start, End: start.Add(80 * time.Second), Eligible: lf.Eligible, OrderingAmbiguous: lf.OrderingAmbiguous, MaskedRules: lf.MaskedFeatures, Scores: map[string]float64{}, Abstentions: map[string][]string{}}
		if !lf.Eligible {
			addCoverage(g, "longflow_incomplete:"+lf.ID)
		}
		for _, rule := range longRules {
			feature, ok := lf.Features[rule.ID]
			if !ok {
				return fmt.Errorf("missing longflow feature%s", rule.ID)
			}
			if rule.ID == "lf05_immediate_reply_share" && lf.OrderingAmbiguous && feature.Eligible {
				return fmt.Errorf("ambiguous longflow reply feature cannot be enabled")
			}
			if !feature.Eligible {
				if w.Abstentions == nil {
					w.Abstentions = map[string][]string{}
				}
				w.Abstentions[rule.ID] = append([]string(nil), feature.Reasons...)
				continue
			}
			if !lf.Eligible || len(feature.Reasons) > 0 || feature.Value == nil || feature.Support < minimumLongSupport(rule.ID) || math.IsNaN(*feature.Value) || math.IsInf(*feature.Value, 0) || *feature.Value < 0 || *feature.Value > 1 {
				return fmt.Errorf("invalid/unsupported longflow feature%s", rule.ID)
			}
			w.Scores[rule.ID] = *feature.Value
		}
		g.Windows = append(g.Windows, w)
	}
	for id := range known {
		if !seen[id] {
			return fmt.Errorf("longflow missing applicable flow%s", id)
		}
	}
	return nil
}
func appendLongflow(groups []Group, indexPath string, f Freeze) error {
	var index Index
	if _, err := read(indexPath, &index); err != nil {
		return err
	}
	refs := map[string]ReportRef{}
	for _, r := range index.Reports {
		refs[r.GroupID] = r
	}
	for i := range groups {
		g := &groups[i]
		ref := refs[g.Metadata.GroupID]
		if ref.LongflowPath == "" {
			addCoverage(g, "missing_longflow_report")
			continue
		}
		p := ref.LongflowPath
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(indexPath), p)
		}
		var report LongReport
		if _, err := read(p, &report); err != nil {
			addCoverage(g, "longflow_read_error")
			continue
		}
		if err := appendLongReport(g, report, f); err != nil {
			return err
		}
	}
	return nil
}

func minimumLongSupport(id string) uint64 {
	if id == "lf05_immediate_reply_share" || id == "lf06_directional_regularity" {
		return 8
	}
	return 16
}

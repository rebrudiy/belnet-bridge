package main

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"
)

func hexSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func validateFreeze(f Freeze) error {
	if f.AnalysisContract != ConservativeAnalysis || f.Schema != 4 || (f.Stage != "B1" && f.Stage != "B2") || f.Viability != "proceed" || f.Frozen.IsZero() {
		return fmt.Errorf("G03 schema4 B1/B2 freeze and explicit StageA proceed required")
	}
	if f.MeasuredSeconds != 80 || f.CaptureSeconds != 82 || f.PrefixGrace != 2 || f.WindowSeconds != 2 || f.Cooldown != 30 || f.CaptureCap != 256*1024*1024 || f.Budget != .05 || f.FlowBudget != .05 {
		return fmt.Errorf("frozen80s/82s/2sgrace joint5%% timing/capture contract mismatch")
	}
	if !hexSHA(f.OrderingSHA) || !hexSHA(f.LongflowDefinitionsSHA) || !hexSHA(f.LongflowExtractorSHA) || !hexSHA(f.EnsembleSHA) || !hexSHA(f.WindowDefinitionsSHA) {
		return fmt.Errorf("combined ordering/window/longflow/ensemble pins required")
	}
	if !hexSHA(f.DefinitionsSHA) || !hexSHA(f.EngineSHA) || !hexSHA(f.CollectorSHA) || !hexSHA(f.ObserverSHA) || f.ObserverVersion != "g04-header-observer-v1" || f.ObserverSchema != 6 || f.CoverageSHA != SupportedCoverageSHA || len(f.Groups) == 0 {
		return fmt.Errorf("collector/observer/engine/definitions SHA pins and assignments required")
	}
	if f.Stage == "B2" && (!hexSHA(f.DevelopmentSHA) || !hexSHA(f.PolicySHA)) {
		return fmt.Errorf("B2 requires development_freeze_sha256 and policy_sha256")
	}
	if len(f.WindowOffsets) == 0 || len(f.WindowOffsets) > 45 {
		return fmt.Errorf("bounded nonempty frozen window schedule required")
	}
	previous := -1
	for _, offset := range f.WindowOffsets {
		if offset < 0 || offset <= previous || offset > f.MeasuredSeconds-f.WindowSeconds {
			return fmt.Errorf("frozen window schedule invalid")
		}
		previous = offset
	}
	seen := map[string]bool{}
	paired := map[string]string{}
	for _, a := range f.Groups {
		if a.GroupID == "" || seen[a.GroupID] || a.Profile == "" || (a.Class != "benign" && a.Class != "belnet") || a.SourceWorkloadID == "" || a.Scope != "primary" || a.ClientStack == "" {
			return fmt.Errorf("invalid/repeated/nonprimary frozen assignment %s", a.GroupID)
		}
		if (f.Stage == "B1" && a.Split != "train" && a.Split != "validation") || (f.Stage == "B2" && a.Split != "test") {
			return fmt.Errorf("%s rejects split%s before report/index/scoring", f.Stage, a.Split)
		}
		if a.Class == "benign" && a.Transport != "ordinary-tls" {
			return fmt.Errorf("primary benign must be ordinary TLS; REALITY-other-payload is diagnostic only")
		}
		if a.Class == "belnet" && a.Transport != "reality" {
			return fmt.Errorf("primary positive must be declared actual BelNet REALITY transport")
		}
		if split, ok := paired[a.SourceWorkloadID]; ok && split != a.Split {
			return fmt.Errorf("paired source workload%s crosses splits", a.SourceWorkloadID)
		}
		paired[a.SourceWorkloadID] = a.Split
		seen[a.GroupID] = true
	}
	return nil
}
func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func sameCore(a, b Assignment) bool {
	return a.GroupID == b.GroupID && a.Split == b.Split && a.Class == b.Class && a.Profile == b.Profile
}
func addCoverage(g *Group, reason string) {
	g.Complete = false
	for _, r := range g.Reasons {
		if r == reason {
			return
		}
	}
	g.Reasons = append(g.Reasons, reason)
}

// Preflight the entire typed index BEFORE opening any observer report. In B1 a
// test reference is an error, never a silently skipped capture.
func preflightIndex(index Index, f Freeze, fit bool) error {
	if index.Schema != 4 || index.Stage != f.Stage || (fit && f.Stage != "B1") {
		return fmt.Errorf("typed schema4 stage-matched index required; fitting is B1 only")
	}
	expected := map[string]Assignment{}
	for _, a := range f.Groups {
		expected[a.GroupID] = a
	}
	seen := map[string]bool{}
	for _, ref := range index.Reports {
		if f.Stage == "B1" && ref.Split == "test" {
			return fmt.Errorf("B1 test reference rejected before opening%s", ref.Path)
		}
		a, ok := expected[ref.GroupID]
		if !ok || seen[ref.GroupID] || ref.Split != a.Split || ref.Path == "" {
			return fmt.Errorf("unknown/mismatched/repeated index group%s", ref.GroupID)
		}
		seen[ref.GroupID] = true
	}
	return nil
}
func loadGroups(indexPath string, f Freeze, freezeSHA string, fit bool) ([]Group, error) {
	var index Index
	if _, err := read(indexPath, &index); err != nil {
		return nil, err
	}
	if err := preflightIndex(index, f, fit); err != nil {
		return nil, err
	}
	origins, err := captureOrigins(f, filepath.Dir(indexPath))
	if err != nil {
		return nil, err
	}
	refs := map[string]ReportRef{}
	for _, ref := range index.Reports {
		refs[ref.GroupID] = ref
	}
	groups := []Group{}
	for _, a := range f.Groups {
		g := Group{Metadata: Metadata{Assignment: a}, Complete: true, Reasons: []string{}, Windows: []Window{}, Diagnostics: []Window{}}
		for _, reason := range index.CoverageErrors {
			addCoverage(&g, "index_coverage: "+reason)
		}
		ref, ok := refs[a.GroupID]
		if !ok {
			addCoverage(&g, "missing_declared_group_report")
			groups = append(groups, g)
			continue
		}
		for _, reason := range ref.CoverageErrors {
			addCoverage(&g, "collector_coverage: "+reason)
		}
		path := ref.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(indexPath), path)
		}
		var c Capture
		digest, err := read(path, &c)
		if err != nil {
			addCoverage(&g, "observer_report_read_or_decode_error: "+err.Error())
			groups = append(groups, g)
			continue
		}
		g.SourceSHA = digest
		g.PCAPSHA = c.PCAPSHA
		g.OrderingSHA = c.OrderingSHA
		g.CoverageSHA = c.CoverageSHA
		g.ZeroPayloadSetupOnly = c.ZeroPayloadSetupOnly
		g.HeaderEvidenceAbsent = c.HeaderEvidenceAbsent
		g.Metadata = c.Metadata
		g.Metadata.Assignment = a
		if !sameCore(a, c.Metadata.Assignment) || !compatibleOptional(a, c.Metadata.Assignment) {
			addCoverage(&g, "frozen_assignment_metadata_mismatch")
			groups = append(groups, g)
			continue
		}
		origin := origins[a.GroupID]
		contractValid := true
		start := time.UnixMicro(c.Metadata.MeasurementStartMicros).UTC()
		end := start.Add(time.Duration(f.MeasuredSeconds) * time.Second)
		if c.Metadata.MeasurementStartMicros <= 0 || !c.Metadata.CaptureStarted.After(origin.Frozen) || !start.After(origin.Frozen) || c.Metadata.CaptureStarted.After(start) || c.Metadata.CaptureEnded.Before(end.Add(time.Duration(f.PrefixGrace)*time.Second)) || c.Metadata.FreezeSHA != origin.SHA || c.Metadata.CaptureCap != f.CaptureCap || c.Metadata.MeasuredSeconds != f.MeasuredSeconds || c.Metadata.PrefixGrace != f.PrefixGrace || !sameInts(c.Metadata.WindowOffsets, f.WindowOffsets) {
			addCoverage(&g, "capture_or_primary_horizon_not_pinned_fresh_VM_contract")
			contractValid = false
		}
		if c.Schema != 6 || c.CoverageSHA != f.CoverageSHA || c.OrderingSHA != f.OrderingSHA || c.Version != f.ObserverVersion || c.MeasurementStart == nil || c.MeasurementEnd == nil || !hexSHA(c.PCAPSHA) || len(c.GroupWindows) != len(f.WindowOffsets) {
			addCoverage(&g, "observer_schema_version_or_window_count")
			contractValid = false
		}
		if c.MeasurementStart != nil && !c.MeasurementStart.Equal(start) || c.MeasurementEnd != nil && !c.MeasurementEnd.Equal(end) {
			addCoverage(&g, "observer_primary_interval_mismatch")
			contractValid = false
		}

		g.HeaderEvidenceAbsent = knownPrimaryHeaderAbsence(c, start, end)
		for _, reason := range validateHeaderEvidence(c, start, end) {
			addCoverage(&g, reason)
			contractValid = false
		}
		if c.Anchor == nil && !g.HeaderEvidenceAbsent {
			addCoverage(&g, "missing_tls23_anchor")
		} else if c.Anchor != nil && c.Anchor.Before(c.Metadata.CaptureStarted) {
			addCoverage(&g, "header_anchor_before_capture_context")
		}
		if !c.Coverage {
			addCoverage(&g, "observer_coverage_incomplete")
		}
		for _, reason := range c.GlobalReasons {
			addCoverage(&g, reason)
		}
		for i, w := range c.GroupWindows {
			if i >= len(f.WindowOffsets) || !w.Start.Equal(start.Add(time.Duration(f.WindowOffsets[i])*time.Second)) || w.End.Sub(w.Start) != 2*time.Second || !w.Primary {
				addCoverage(&g, "declared_group_window_schedule_mismatch")
			}
			if !w.Eligible {
				addCoverage(&g, "incomplete_declared_group_window")
			}
		}
		var inventoryErrors []string
		g.PrimaryFlowIDs, inventoryErrors = primaryInventory(c.Flows, start, end)
		if len(g.PrimaryFlowIDs) == 0 {
			inventoryErrors = append(inventoryErrors, "no_primary_flow_inventory")
		}
		for _, reason := range inventoryErrors {
			addCoverage(&g, reason)
			contractValid = false
		}
		g.PrimaryTLSFlows = map[string]bool{}
		g.PrimaryHeaderCounts = map[string]uint64{}
		for _, flow := range c.Flows {
			g.PrimaryTLSFlows[flow.ID] = flow.PrimaryHeaderCount != nil && *flow.PrimaryHeaderCount > 0
			if flow.PrimaryHeaderCount != nil {
				g.PrimaryHeaderCounts[flow.ID] = *flow.PrimaryHeaderCount
			}
		}
		observedOrdinals := map[uint64]rawRecordIdentity{}
		ids := map[string]bool{}
		fixedByFlow := map[string]map[int64]bool{}
		prefixByFlow := map[string]int{}
		for _, w := range c.Windows {
			w.Scores = nil
			if !contractValid {
				w.Eligible = false
			}
			if w.GroupID != a.GroupID || w.Split != a.Split || w.Class != a.Class || w.Profile != a.Profile || w.ID == "" || w.FlowID == "" || ids[w.ID] || w.End.Sub(w.Start) != 2*time.Second {
				addCoverage(&g, "window_provenance_mismatch")
				continue
			}
			ids[w.ID] = true
			if w.Kind == "phase_fixed" {
				offset := w.Start.Sub(start)
				valid := false
				for _, want := range f.WindowOffsets {
					if offset == time.Duration(want)*time.Second {
						valid = true
					}
				}
				if !valid || !w.Primary {
					addCoverage(&g, "flow_fixed_window_schedule_mismatch")
				}
				if fixedByFlow[w.FlowID] == nil {
					fixedByFlow[w.FlowID] = map[int64]bool{}
				}
				key := int64(offset)
				if fixedByFlow[w.FlowID][key] {
					addCoverage(&g, "duplicate_flow_fixed_offset")
				}
				fixedByFlow[w.FlowID][key] = true
			} else if w.Kind == "flow-prefix" {
				if !w.Start.Before(start) && w.Start.Before(end) {
					prefixByFlow[w.FlowID]++
					if !w.Primary {
						addCoverage(&g, "in_horizon_prefix_hidden_from_primary")
					}
				} else if w.Start.Before(start) || w.Primary || w.Status != "not_applicable" {
					addCoverage(&g, "prefix_outside_primary_horizon_mismatch")
				}
			} else if w.Kind == "bootstrap-prefix" {
				if !w.Start.Before(start) || w.Primary {
					addCoverage(&g, "invalid_preprimary_context_prefix")
				}
			} else {
				addCoverage(&g, "unknown_window_kind")
			}
			if w.Kind == "bootstrap-prefix" || !w.Primary || w.Status == "not_applicable" {
				g.Diagnostics = append(g.Diagnostics, w)
				continue
			}
			if !w.Eligible {
				addCoverage(&g, "incomplete_flow_or_reconnect_window")
			}
			if len(w.Events) > 64 {
				addCoverage(&g, "feature_event_bound_exceeded")
				w.Eligible = false
			}
			previous := int64(-1)
			var previousRaw int64
			var previousOrdinal uint64
			havePrevious := false
			seenOrdinals := map[uint64]bool{}
			for _, e := range w.Events {
				if e.Ordinal == 0 || e.At < 0 || e.At >= 2_000_000 || e.At < previous || (e.Direction != 1 && e.Direction != -1) || e.Bytes < 5 {
					addCoverage(&g, "malformed_feature_events")
					w.Eligible = false
				}
				if e.RawNS < w.Start.UnixNano() || e.RawNS >= w.End.UnixNano() || (e.RawNS-w.Start.UnixNano())/1000 != e.At || havePrevious && (e.RawNS < previousRaw || e.RawNS == previousRaw && e.Ordinal <= previousOrdinal) {
					addCoverage(&g, "logical_metadata_order_or_raw_timestamp_mismatch")
					w.Eligible = false
				}
				if seenOrdinals[e.Ordinal] {
					addCoverage(&g, "duplicate_raw_record_ordinal")
					w.Eligible = false
				}
				seenOrdinals[e.Ordinal] = true
				identity := rawRecordIdentity{e.RawNS, e.Direction, e.Bytes, w.FlowID}
				if old, ok := observedOrdinals[e.Ordinal]; ok && old != identity {
					addCoverage(&g, "conflicting_global_raw_record_ordinal")
					w.Eligible = false
				}
				observedOrdinals[e.Ordinal] = identity
				previousRaw = e.RawNS
				previousOrdinal = e.Ordinal
				havePrevious = true
				previous = e.At
			}
			visible, causal := visibleAmbiguity(w.Events)
			if causal {
				addCoverage(&g, "selected_per_direction_causal_violation")
				w.Eligible = false
			}
			if visible && !w.OrderingAmbiguous {
				addCoverage(&g, "visible_crossdirection_ambiguity_unreported")
				w.Eligible = false
			}
			g.Windows = append(g.Windows, w)
		}
		flowIDs := map[string]bool{}
		for _, flow := range c.Flows {
			if flow.ID == "" || flowIDs[flow.ID] {
				addCoverage(&g, "invalid_or_duplicate_flow_metadata")
			}
			flowIDs[flow.ID] = true
			if len(fixedByFlow[flow.ID]) != len(f.WindowOffsets) {
				addCoverage(&g, "missing_declared_flow_fixed_windows")
			}
			if flow.First != nil && !flow.First.Before(start) && flow.First.Before(end) && prefixByFlow[flow.ID] != 1 {
				addCoverage(&g, "missing_or_duplicate_primary_flow_prefix")
			}
		}
		primaryIDs := map[string]bool{}
		for _, id := range g.PrimaryFlowIDs {
			primaryIDs[id] = true
		}
		for _, w := range g.Windows {
			if !primaryIDs[w.FlowID] {
				addCoverage(&g, "window_outside_primary_flow_inventory")
			}
		}
		for _, w := range g.Windows {
			if !flowIDs[w.FlowID] {
				addCoverage(&g, "window_flow_not_in_observer_inventory")
			}
		}
		setUncertainty(&g, c)
		if !g.Complete && !g.UncertaintyBounded {
			for i := range g.Windows {
				g.Windows[i].Eligible = false
				g.Windows[i].Scores = nil
				g.Windows[i].Reasons = append(g.Windows[i].Reasons, "unverified_global_or_inventory_scope")
			}
		}
		groups = append(groups, g)
	}
	return groups, nil
}
func groupErrors(groups []Group) []string {
	errors := []string{}
	for _, g := range groups {
		if !g.Complete {
			errors = append(errors, fmt.Sprintf("%s: %v", g.Metadata.GroupID, g.Reasons))
		}
	}
	return errors
}
func policyBinding(p Policy, f Freeze, freezeSHA, policySHA string) error {
	a, _ := json.Marshal(p.EngineeredRules)
	b, _ := json.Marshal(f.EngineeredRules)
	if (len(p.EngineeredRules) > 0 || len(f.EngineeredRules) > 0) && string(a) != string(b) {
		return fmt.Errorf("policy engineered rules differ from frozen definitions")
	}
	if f.Stage == "B1" {
		if p.FreezeSHA != freezeSHA {
			return fmt.Errorf("B1 policy/development freeze mismatch")
		}
	} else {
		if p.FreezeSHA != f.DevelopmentSHA || policySHA != f.PolicySHA || !f.Frozen.After(p.FrozenAt) {
			return fmt.Errorf("B2 requires exact policy/development SHA and a later collection freeze")
		}
	}
	if p.LastDevelopmentCapture.IsZero() || !p.FrozenAt.After(p.LastDevelopmentCapture) {
		return fmt.Errorf("policy freeze must follow all development captures")
	}
	return nil
}
func finiteScores(groups []Group) error {
	for _, g := range groups {
		for _, w := range g.Windows {
			for _, v := range w.Scores {
				if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
					return fmt.Errorf("invalid score")
				}
			}
		}
	}
	return nil
}

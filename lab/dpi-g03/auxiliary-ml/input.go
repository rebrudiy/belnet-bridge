package main

import (
	"fmt"
	"path/filepath"
	"time"
)

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
		g.Metadata = c.Metadata
		g.Metadata.Assignment = a
		if !sameCore(a, c.Metadata.Assignment) || !compatibleOptional(a, c.Metadata.Assignment) {
			addCoverage(&g, "frozen_assignment_metadata_mismatch")
			groups = append(groups, g)
			continue
		}
		contractValid := true
		start := time.UnixMicro(c.Metadata.MeasurementStartMicros).UTC()
		end := start.Add(time.Duration(f.MeasuredSeconds) * time.Second)
		if c.Metadata.MeasurementStartMicros <= 0 || !c.Metadata.CaptureStarted.After(f.Frozen) || !start.After(f.Frozen) || c.Metadata.CaptureStarted.After(start) || c.Metadata.CaptureEnded.Before(end.Add(time.Duration(f.PrefixGrace)*time.Second)) || c.Metadata.FreezeSHA != f.CollectorSHA || c.Metadata.CaptureCap != f.CaptureCap || c.Metadata.MeasuredSeconds != f.MeasuredSeconds || c.Metadata.PrefixGrace != f.PrefixGrace || !sameInts(c.Metadata.WindowOffsets, f.WindowOffsets) {
			addCoverage(&g, "capture_or_primary_horizon_not_pinned_fresh_VM_contract")
			contractValid = false
		}
		if c.Schema != 4 || c.OrderingSHA != f.OrderingSHA || c.Version != f.ObserverVersion || c.MeasurementStart == nil || c.MeasurementEnd == nil || !hexSHA(c.PCAPSHA) || len(c.GroupWindows) != len(f.WindowOffsets) {
			addCoverage(&g, "observer_schema_version_or_window_count")
			contractValid = false
		}
		if c.MeasurementStart != nil && !c.MeasurementStart.Equal(start) || c.MeasurementEnd != nil && !c.MeasurementEnd.Equal(end) {
			addCoverage(&g, "observer_primary_interval_mismatch")
			contractValid = false
		}
		if c.Anchor == nil {
			addCoverage(&g, "missing_tls23_anchor")
		} else if c.Anchor.Before(start) {
			addCoverage(&g, "bootstrap_before_prelaunch_primary_measurement")
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
		g.PrimaryTLSFlows = map[string]bool{}
		for _, flow := range c.Flows {
			g.PrimaryTLSFlows[flow.ID] = flow.First != nil && !flow.First.Before(start) && flow.First.Before(end)
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
				addCoverage(&g, "bootstrap_before_prelaunch_primary_measurement")
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
				if e.Ordinal == 0 || e.At < 0 || e.At >= 2_000_000 || e.At < previous || (e.Direction != 1 && e.Direction != -1) || e.Bytes < 5 || e.Bytes > 65540 {
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
			if !validOrderingMask(w) {
				addCoverage(&g, "ordering_mask_mismatch")
				w.Eligible = false
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
		for _, w := range g.Windows {
			if !flowIDs[w.FlowID] {
				addCoverage(&g, "window_flow_not_in_observer_inventory")
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

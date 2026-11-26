package main

import "time"

// validateFlowInventory never creates feature windows. Physical primary flow IDs
// remain separate from whether a TLS record or a supported ML vector exists.
func validateFlowInventory(g *Group, c Capture, start, end time.Time) {
	g.PrimaryFlows = map[string]bool{}
	g.PrimaryTLSFlows = map[string]bool{}
	seen := map[string]bool{}
	havePrimarySYN := false
	allPrimaryZero := true
	var earliest *time.Time
	for _, flow := range c.Flows {
		if flow.ID == "" || seen[flow.ID] {
			addCoverage(g, "invalid_or_duplicate_flow_metadata")
			continue
		}
		seen[flow.ID] = true
		if flow.PrimaryScope == nil || flow.RawPayload == nil {
			addCoverage(g, "missing_v3_primary_scope_or_raw_payload_counter")
			allPrimaryZero = false
			continue
		}
		primary := *flow.PrimaryScope
		if flow.SYN != nil {
			derived := flow.SYN.Before(end) && (flow.Closed == nil || !flow.Closed.Before(start))
			if primary != derived {
				addCoverage(g, "primary_scope_disagrees_with_flow_lifetime")
			}
		}
		hasTLS := flow.First != nil && !flow.First.Before(start) && flow.First.Before(end)
		if hasTLS && !primary {
			addCoverage(g, "primary_TLS_hidden_from_flow_inventory")
		}
		expectedState := "payload_observed"
		switch {
		case flow.SYN == nil:
			expectedState = "unknown_missing_initial_syn"
		case *flow.RawPayload != 0:
			expectedState = "payload_observed"
		case !flow.SYNACK:
			expectedState = "setup_incomplete_no_tls_evidence"
		default:
			expectedState = "handshake_observed_no_tls_evidence"
		}
		if flow.SetupState != expectedState {
			addCoverage(g, "setup_state_disagrees_with_wire_counters")
		}
		if *flow.RawPayload == 0 {
			for _, w := range c.Windows {
				if w.FlowID == flow.ID && (len(w.Events) > 0 || w.TotalRecords != 0) {
					addCoverage(g, "raw_zero_flow_has_TLS_window_metadata")
				}
			}
		}
		if flow.First != nil {
			if *flow.RawPayload == 0 {
				addCoverage(g, "TLS_anchor_with_zero_raw_payload")
			}
			if earliest == nil || flow.First.Before(*earliest) {
				at := *flow.First
				earliest = &at
			}
		}
		if !primary {
			continue
		}
		g.PrimaryFlows[flow.ID] = true
		g.PrimaryTLSFlows[flow.ID] = hasTLS
		if flow.SYN == nil {
			addCoverage(g, "primary_flow_missing_initial_syn")
		}
		if *flow.RawPayload != 0 && (flow.SYN == nil || !flow.SYNACK) {
			addCoverage(g, "primary_payload_with_missing_handshake")
		}
		if flow.SYN == nil || *flow.RawPayload != 0 {
			allPrimaryZero = false
		}
		if flow.SYN != nil && !flow.SYN.Before(start) && flow.SYN.Before(end) {
			havePrimarySYN = true
		}
	}
	if len(g.PrimaryFlows) == 0 {
		addCoverage(g, "no_actual_primary_flow_activity")
	}
	expectedZero := len(g.PrimaryFlows) > 0 && havePrimarySYN && allPrimaryZero
	if c.ZeroPayloadSetupOnly != expectedZero {
		addCoverage(g, "zero_payload_setup_only_contract_mismatch")
	}
	if c.ZeroPayloadSetupOnly && c.CoverageSHA != CoverageSHA {
		addCoverage(g, "zero_payload_anchor_waiver_without_coverage_pin")
	}
	if (earliest == nil) != (c.Anchor == nil) || earliest != nil && c.Anchor != nil && !earliest.Equal(*c.Anchor) {
		addCoverage(g, "group_anchor_disagrees_with_flow_inventory")
	}
	if c.ZeroPayloadSetupOnly {
		for _, w := range c.Windows {
			if w.Primary && w.Status != "not_applicable" && (len(w.Events) > 0 || w.TotalRecords != 0) {
				addCoverage(g, "zero_payload_primary_has_TLS_evidence")
			}
		}
		for _, w := range c.GroupWindows {
			if len(w.Events) > 0 || w.TotalRecords != 0 {
				addCoverage(g, "zero_payload_group_has_TLS_evidence")
			}
		}
	}
}

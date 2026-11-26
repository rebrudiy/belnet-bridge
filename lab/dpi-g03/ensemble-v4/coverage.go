package main

import (
	"fmt"
	"time"
)

const SupportedCoverageSHA = "5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810"

func validateZeroPayloadSetup(c Capture, start, end time.Time) error {
	if c.Anchor != nil && c.Anchor.Before(end) {
		return fmt.Errorf("TLS anchor contradicts zero-payload flag")
	}
	var first *time.Time
	for _, flow := range c.Flows {
		if flow.First != nil && (first == nil || flow.First.Before(*first)) {
			first = flow.First
		}
	}
	if (c.Anchor == nil) != (first == nil) || c.Anchor != nil && !c.Anchor.Equal(*first) {
		return fmt.Errorf("global TLS anchor does not match flow inventory")
	}
	count := 0
	ids := map[string]bool{}
	for _, flow := range c.Flows {
		if flow.PrimaryScope == nil || flow.RawPayload == nil {
			return fmt.Errorf("missing primary/raw-payload inventory")
		}
		if flow.Syn != nil {
			expected := flow.Syn.Before(end) && (flow.Closed == nil || !flow.Closed.Before(start))
			if expected != *flow.PrimaryScope {
				return fmt.Errorf("primary_flow_scope_lifetime_mismatch")
			}
			if flow.Closed != nil && flow.Closed.Before(*flow.Syn) {
				return fmt.Errorf("flow_close_precedes_syn")
			}
		} else if flow.First != nil && flow.First.Before(end) && (flow.Closed == nil || !flow.Closed.Before(start)) && !*flow.PrimaryScope {
			return fmt.Errorf("tls_primary_flow_hidden_by_scope")
		}
		if !*flow.PrimaryScope {
			continue
		}
		if flow.ID == "" || ids[flow.ID] || flow.Syn == nil || flow.Syn.Before(start) || !flow.Syn.Before(end) || *flow.RawPayload != 0 || flow.First != nil {
			return fmt.Errorf("not a captured SYN-only primary attempt")
		}
		ids[flow.ID] = true
		count++
	}
	if count == 0 {
		return fmt.Errorf("no primary attempts")
	}
	for _, w := range append(append([]Window(nil), c.GroupWindows...), c.Windows...) {
		inside := !w.Start.Before(start) && !w.End.After(end)
		if inside && (len(w.Events) > 0 || w.TotalRecords > 0) {
			return fmt.Errorf("TLS records contradict zero-payload primary interval")
		}
		for _, e := range w.Events {
			if e.RawNS >= start.UnixNano() && e.RawNS < end.UnixNano() {
				return fmt.Errorf("primary TLS metadata contradicts zero-payload flag")
			}
		}
	}
	for _, w := range c.Windows {
		if w.Primary && w.Status != "not_applicable" && !ids[w.FlowID] {
			return fmt.Errorf("undeclared primary flow")
		}
	}
	return nil
}

func primaryInventory(flows []FlowSummary, start, end time.Time) (ids []string, reasons []string) {
	seen := map[string]bool{}
	for _, flow := range flows {
		if flow.ID == "" || seen[flow.ID] {
			reasons = append(reasons, "invalid_or_duplicate_primary_inventory_id")
			continue
		}
		seen[flow.ID] = true
		if flow.PrimaryScope == nil || flow.RawPayload == nil {
			reasons = append(reasons, "primary_flow_inventory_missing")
			continue
		}
		if flow.Syn != nil {
			expected := flow.Syn.Before(end) && (flow.Closed == nil || !flow.Closed.Before(start))
			if expected != *flow.PrimaryScope {
				reasons = append(reasons, "primary_flow_scope_lifetime_mismatch")
			}
			if flow.Closed != nil && flow.Closed.Before(*flow.Syn) {
				reasons = append(reasons, "flow_close_precedes_syn")
			}
		} else if flow.First != nil && flow.First.Before(end) && (flow.Closed == nil || !flow.Closed.Before(start)) && !*flow.PrimaryScope {
			reasons = append(reasons, "tls_primary_flow_hidden_by_scope")
		}
		if !*flow.PrimaryScope {
			continue
		}
		ids = append(ids, flow.ID)
		if flow.Syn == nil {
			reasons = append(reasons, "primary_initial_syn_missing")
		}
		if flow.SynAck == nil {
			reasons = append(reasons, "primary_synack_inventory_missing")
		}
		if *flow.RawPayload > 0 && (flow.Syn == nil || flow.SynAck == nil || !*flow.SynAck) {
			reasons = append(reasons, "primary_payload_handshake_unknown")
		}
	}
	return ids, reasons
}

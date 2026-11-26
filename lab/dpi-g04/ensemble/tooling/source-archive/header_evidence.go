package main

import "time"

type HeaderStream struct {
	HeaderStarted         *time.Time `json:"current_header_started_utc"`
	HeaderAvailable       *time.Time `json:"current_header_available_utc"`
	PartialHeaderRelevant *bool      `json:"partial_header_relevant_to_primary"`
	CloseAt               *time.Time `json:"close_utc"`
	Direction             int        `json:"direction"`
	ContiguousBytes       uint64     `json:"contiguous_bytes"`
	PeerAcknowledged      uint64     `json:"max_peer_acknowledged_bytes"`
	CloseCaptured         bool       `json:"close_captured"`
	CloseValid            bool       `json:"close_sequence_valid"`
	HeaderPending         int        `json:"header_bytes_pending"`
	BodyRemaining         int        `json:"body_bytes_remaining"`
	ClosedHeaderAbstain   bool       `json:"partial_header_closed_abstention"`
	KnownBodyAbort        bool       `json:"partial_body_known_abort"`
	OpenBody              bool       `json:"open_body_in_progress"`
}

// The unit is a declared record length available in a complete five-byte header.
// It is neither a delivered-byte count nor proof that a TLS session completed.
func validateHeaderEvidence(c Capture, start, end time.Time) []string {
	issues := []string{}
	phaseCounts := map[int64]uint64{}
	for _, w := range c.Windows {
		selected := w.TotalRecords
		if selected > 64 {
			selected = 64
		}
		if uint64(len(w.Events)) != selected {
			issues = append(issues, "selected_headers_do_not_match_total_record_count")
		}
		if w.Kind == "phase_fixed" && w.Primary {
			phaseCounts[w.Start.UnixNano()] += w.TotalRecords
		}
	}
	for _, w := range c.GroupWindows {
		if len(w.Events) != 0 || w.TotalRecords != phaseCounts[w.Start.UnixNano()] {
			issues = append(issues, "group_header_count_or_coverage_event_mismatch")
		}
	}
	if c.EvidenceUnit != "tls23_header_declared_length" {
		issues = append(issues, "header_evidence_unit_mismatch")
	}
	primary, headers := 0, uint64(0)
	primaryValid := true
	for _, flow := range c.Flows {
		if flow.PrimaryScope == nil || flow.HeaderCount == nil || flow.PrimaryHeaderCount == nil || flow.TotalHeaderCount == nil || flow.HeaderParseValid == nil || flow.SequenceCensus == nil || flow.PrimaryHeaderParseValid == nil || flow.PrimarySequenceCensus == nil || flow.PrimaryEvidenceEnd == nil {
			issues = append(issues, "missing_header_flow_inventory_fields")
			primaryValid = false
			continue
		}
		if flow.RawPayload == nil || *flow.RawPayload > uint64(c.Metadata.CaptureCap) || *flow.TotalHeaderCount > *flow.RawPayload/5 {
			issues = append(issues, "header_counts_exceed_captured_TCP_bytes")
		}
		if *flow.PrimaryHeaderCount > *flow.HeaderCount || *flow.HeaderCount > *flow.TotalHeaderCount {
			issues = append(issues, "contradictory_header_inventory_counts")
		}
		if (*flow.HeaderCount == 0) != (flow.First == nil) {
			issues = append(issues, "header_first_pointer_count_mismatch")
		}
		if flow.First != nil && (flow.First.Before(c.Metadata.CaptureStarted) || flow.First.After(c.Metadata.CaptureEnded)) {
			issues = append(issues, "header_first_outside_capture_context")
		}
		if !*flow.PrimaryScope {
			if *flow.PrimaryHeaderCount != 0 {
				issues = append(issues, "primary_headers_hidden_outside_flow_inventory")
			}
			continue
		}
		primary++
		headers += *flow.PrimaryHeaderCount
		expectedEnd := end
		if flow.First != nil && !flow.First.Before(start) && flow.First.Before(end) && flow.First.Add(2*time.Second).After(expectedEnd) {
			expectedEnd = flow.First.Add(2 * time.Second)
		}
		if !flow.PrimaryEvidenceEnd.Equal(expectedEnd) {
			issues = append(issues, "primary_header_evidence_horizon_mismatch")
		}
		if *flow.PrimaryHeaderParseValid != *flow.HeaderParseValid || *flow.PrimarySequenceCensus != *flow.SequenceCensus {
			issues = append(issues, "primary_header_proof_alias_mismatch")
		}
		if *flow.PrimaryHeaderCount > 0 && (flow.First == nil || !flow.First.Before(end)) {
			issues = append(issues, "primary_header_count_without_in_horizon_history")
		}
		if !*flow.HeaderParseValid || !*flow.SequenceCensus {
			primaryValid = false
		}
		if flow.RawPayload != nil && *flow.RawPayload > 0 && len(flow.Streams) == 0 {
			issues = append(issues, "payload_flow_missing_header_stream_proof")
			primaryValid = false
		}
		for _, stream := range flow.Streams {
			for _, stamp := range []*time.Time{stream.HeaderStarted, stream.HeaderAvailable, stream.CloseAt} {
				if stamp != nil && (stamp.Before(c.Metadata.CaptureStarted) || stamp.After(c.Metadata.CaptureEnded)) {
					issues = append(issues, "header_stream_proof_timestamp_outside_capture")
				}
			}
			if stream.HeaderAvailable != nil && (stream.HeaderStarted == nil || stream.HeaderAvailable.Before(*stream.HeaderStarted)) {
				issues = append(issues, "invalid_header_availability_timestamp_proof")
			}
			if stream.CloseCaptured && stream.CloseAt == nil {
				issues = append(issues, "captured_close_missing_timestamp")
			}
			if stream.HeaderPending < 0 || stream.HeaderPending > 4 || stream.BodyRemaining < 0 {
				issues = append(issues, "invalid_partial_header_or_body_inventory")
			}
			if stream.ClosedHeaderAbstain && (!stream.CloseCaptured || !stream.CloseValid || stream.HeaderPending == 0) {
				issues = append(issues, "unproven_partial_header_abstention")
			}
			if stream.ClosedHeaderAbstain && (stream.CloseAt == nil || stream.HeaderStarted == nil || stream.CloseAt.Before(*stream.HeaderStarted)) {
				issues = append(issues, "closed_header_abstention_precedes_header")
			}
			if stream.HeaderPending > 0 {
				if stream.HeaderStarted == nil || stream.PartialHeaderRelevant == nil || stream.HeaderAvailable != nil {
					issues = append(issues, "missing_partial_header_scope_proof")
				} else {
					relevant := stream.HeaderStarted.Before(expectedEnd)
					if relevant != *stream.PartialHeaderRelevant {
						issues = append(issues, "contradictory_partial_header_scope")
					}
					if relevant && !stream.ClosedHeaderAbstain {
						primaryValid = false
					}
				}
			}
			if stream.KnownBodyAbort && (!stream.CloseCaptured || !stream.CloseValid || stream.BodyRemaining == 0) {
				issues = append(issues, "unproven_known_body_abort")
			}
			if stream.KnownBodyAbort && (stream.CloseAt == nil || stream.HeaderAvailable == nil || stream.CloseAt.Before(*stream.HeaderAvailable)) {
				issues = append(issues, "known_body_abort_missing_ordered_header_close_proof")
			}
			if stream.OpenBody && (stream.BodyRemaining == 0 || stream.KnownBodyAbort || stream.CloseCaptured) {
				issues = append(issues, "contradictory_open_body_diagnostic")
			}
		}
		phaseHeaders := uint64(0)
		for _, w := range c.Windows {
			if w.FlowID == flow.ID && w.TotalRecords > *flow.HeaderCount {
				issues = append(issues, "window_header_count_exceeds_capture_inventory")
			}
			if w.FlowID == flow.ID && w.Kind == "phase_fixed" && w.Primary {
				phaseHeaders += w.TotalRecords
			}
			if w.FlowID == flow.ID && w.Kind == "phase_fixed" && w.Primary && w.TotalRecords > *flow.PrimaryHeaderCount {
				issues = append(issues, "sampled_header_count_exceeds_primary_inventory")
			}
		}
		if phaseHeaders > *flow.PrimaryHeaderCount {
			issues = append(issues, "disjoint_sampled_headers_exceed_primary_inventory")
		}
		if c.ZeroPayloadSetupOnly && flow.RawPayload != nil && *flow.RawPayload != 0 {
			issues = append(issues, "zero_payload_flag_hides_header_transport_bytes")
		}
	}
	if c.HeaderEvidenceAbsent && (primary == 0 || headers != 0 || !primaryValid) {
		issues = append(issues, "unverified_header_absence_flag")
	}
	if c.Coverage && !primaryValid {
		issues = append(issues, "complete_header_view_with_invalid_primary_census")
	}
	return issues
}

// Producer absence requires a new in-horizon SYN. Existing observed connections
// can still have a completely known empty header observation over this horizon.
func knownPrimaryHeaderAbsence(c Capture, start, end time.Time) bool {
	if !c.Coverage || len(validateHeaderEvidence(c, start, end)) != 0 {
		return false
	}
	have := false
	for _, flow := range c.Flows {
		if flow.PrimaryScope != nil && *flow.PrimaryScope {
			have = true
			if flow.PrimaryHeaderCount == nil || *flow.PrimaryHeaderCount != 0 {
				return false
			}
		}
	}
	return have
}

package main

const CoverageSemanticsSHA = "5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810"

// primaryScope preserves actual attempts but excludes grace-only connections.
func (p *Parser) primaryScope(f *Flow) bool {
	return f.havePacket && f.minPacketNS < p.measurementEnd && (f.closedNS == 0 || f.closedNS >= p.measurementStart)
}

func (p *Parser) classifySetup(f *Flow) {
	f.PrimaryScope = p.primaryScope(f)
	switch {
	case f.SYN == nil:
		f.SetupState = "unknown_missing_initial_syn"
	case f.RawTCPPayloadBytes != 0:
		f.SetupState = "payload_observed"
	case !f.SYNACK:
		f.SetupState = "setup_incomplete_no_tls_evidence"
	default:
		f.SetupState = "handshake_observed_no_tls_evidence"
	}
}

func (p *Parser) zeroPayloadSetupOnly() bool {
	if p.meta.MeasurementStartMicros == 0 {
		return false
	}
	havePrimarySYN := false
	for _, f := range p.report.Flows {
		if !p.primaryScope(f) {
			continue
		}
		if f.SYN == nil || f.RawTCPPayloadBytes != 0 {
			return false
		}
		at := f.SYN.UnixNano()
		if at >= p.measurementStart && at < p.measurementEnd {
			havePrimarySYN = true
		}
	}
	return havePrimarySYN
}

// Physical primary QC is independent of all sampled windows. Top-level
// incompleteness does not erase sound earlier window observations.
func (p *Parser) primaryFlowCoverageReasons() []string {
	reasons := []string{}
	for _, f := range p.report.Flows {
		if !p.primaryScope(f) {
			continue
		}
		if f.RawTCPPayloadBytes > 0 && (f.SYN == nil || !f.SYNACK) {
			addReason(&reasons, "primary_payload_with_missing_handshake")
		}
		for reason, at := range f.issueAt {
			if at < p.measurementEnd {
				addReason(&reasons, "primary_flow_fault: "+reason)
			}
		}
	}
	return reasons
}

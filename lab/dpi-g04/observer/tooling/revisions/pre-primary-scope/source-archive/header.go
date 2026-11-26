package main

import "time"

// StreamEvidence contains metadata only; retained encrypted stream bytes are
// private parser memory and never included in JSON.
type StreamEvidence struct {
	Direction                     int    `json:"direction"`
	ContiguousBytes               uint32 `json:"contiguous_bytes"`
	MaxPeerAcknowledgedBytes      uint32 `json:"max_peer_acknowledged_bytes"`
	CloseCaptured                 bool   `json:"close_captured"`
	CloseSequenceValid            bool   `json:"close_sequence_valid"`
	FINCaptured                   bool   `json:"fin_captured"`
	RSTCaptured                   bool   `json:"rst_captured"`
	HeaderBytesPending            int    `json:"header_bytes_pending"`
	RecordType                    byte   `json:"record_type"`
	DeclaredRecordBytes           int    `json:"declared_record_bytes"`
	BodyBytesRemaining            int    `json:"body_bytes_remaining"`
	PartialHeaderClosedAbstention bool   `json:"partial_header_closed_abstention"`
	PartialBodyKnownAbort         bool   `json:"partial_body_known_abort"`
	OpenBodyInProgress            bool   `json:"open_body_in_progress"`
}

func (s *Stream) remember(data []byte, at int64) bool {
	if len(data) > MaxConsumedHistory-s.owner.historyBytes {
		s.fail("tcp_history_byte_censored", at)
		return false
	}
	s.history = append(s.history, data...)
	s.owner.historyBytes += len(data)
	s.owner.report.ConsumedHistoryHighWater = max(s.owner.report.ConsumedHistoryHighWater, s.owner.historyBytes)
	return true
}
func (s *Stream) observeACK(ack uint32, at int64) {
	offset := ack - s.base
	if offset > 0x7fffffff {
		return
	} // ACK preceding SYN data origin, including fixture zero ACKs.
	if offset > s.maxACK {
		s.maxACK = offset
		s.ackAt = at
	}
}
func (s *Stream) observeClose(seq uint32, at int64, rst bool) {
	offset := seq - s.base
	if rst {
		if s.rstSeen && s.rstOffset != offset {
			s.flow.issue("conflicting_rst_sequence", at)
		}
		s.rstSeen = true
		s.rstOffset = offset
		s.rstAt = at
	} else {
		if s.finSeen && s.finOffset != offset {
			s.flow.issue("conflicting_fin_sequence", at)
		}
		s.finSeen = true
		s.finOffset = offset
		s.finAt = at
	}
}
func (s *Stream) acknowledgedBytes() uint32 {
	// A FIN consumes one sequence number, unlike TLS/TCP payload bytes.
	n := s.maxACK
	if s.finSeen && n > s.finOffset {
		n--
	}
	return n
}
func (s *Stream) closeSequenceValid() bool {
	return (!s.finSeen || s.finOffset == s.pos) && (!s.rstSeen || s.rstOffset == s.pos)
}
func (s *Stream) closed() bool { return s.finSeen || s.flow.RSTCaptured }
func (s *Stream) finalizeCensus() {
	if s.acknowledgedBytes() > s.pos {
		s.flow.issue("tcp_acknowledges_uncaptured_bytes", s.ackAt)
	}
	if !s.closeSequenceValid() {
		at := s.finAt
		if s.rstSeen {
			at = s.rstAt
		}
		s.flow.issue("tcp_close_sequence_mismatch", at)
	}
	// Body bytes are not a prerequisite for a complete header observation.
	// A partial header is unsupported evidence unless a verified captured close
	// proves a bounded aborted prefix. New SYN/reuse alone never proves this.
	if !s.inRecord && s.headerN > 0 {
		valid := s.closed() && s.closeSequenceValid() && s.acknowledgedBytes() <= s.pos && len(s.pending) == 0 && !s.bad
		if !valid {
			s.flow.issue("partial_final_tls_header", s.headerStartNS)
		}
	}
}
func (p *Parser) finalizeHeaderEvidence() {
	for _, f := range p.report.Flows {
		f.TCPSequenceCensusComplete = f.SYN != nil && (f.RawTCPPayloadBytes == 0 || f.SYNACK)
		f.TLSHeaderParseValid = true
		f.IssueTimestamps = map[string]time.Time{}
		for reason, at := range f.issueAt {
			f.IssueTimestamps[reason] = utc(at)
			if at >= p.measurementEnd {
				continue
			}
			if reason == "malformed_tls" || reason == "partial_final_tls_header" {
				f.TLSHeaderParseValid = false
			} else {
				f.TCPSequenceCensusComplete = false
			}
		}
		if len(p.global) > 0 {
			f.TCPSequenceCensusComplete = false
		}
		f.Streams = []StreamEvidence{}
		for _, direction := range []int{1, -1} {
			s := f.streams[direction]
			if s == nil {
				continue
			}
			headerN := 0
			if !s.inRecord {
				headerN = s.headerN
			}
			partialBody := s.inRecord && s.remaining > 0
			valid := f.TCPSequenceCensusComplete && f.TLSHeaderParseValid && !s.bad && len(s.pending) == 0 && s.closeSequenceValid() && s.acknowledgedBytes() <= s.pos
			f.Streams = append(f.Streams, StreamEvidence{Direction: direction, ContiguousBytes: s.pos, MaxPeerAcknowledgedBytes: s.acknowledgedBytes(), CloseCaptured: s.closed(), CloseSequenceValid: s.closeSequenceValid(), FINCaptured: s.finSeen, RSTCaptured: f.RSTCaptured, HeaderBytesPending: headerN, RecordType: s.kind, DeclaredRecordBytes: s.recordSize, BodyBytesRemaining: s.remaining, PartialHeaderClosedAbstention: headerN > 0 && s.closed() && valid, PartialBodyKnownAbort: partialBody && s.closed() && valid, OpenBodyInProgress: partialBody && !s.closed()})
		}
		f.HeaderEvidenceAbsent = f.PrimaryScope && f.PrimaryTLS23Headers == 0 && f.TCPSequenceCensusComplete && f.TLSHeaderParseValid && (f.First == nil || f.firstNS >= p.measurementStart)
	}
}
func (p *Parser) headerEvidenceAbsent() bool {
	if p.meta.MeasurementStartMicros == 0 {
		return false
	}
	havePrimarySYN := false
	for _, f := range p.report.Flows {
		if !f.PrimaryScope {
			continue
		}
		if !f.HeaderEvidenceAbsent {
			return false
		}
		if f.SYN != nil && f.SYN.UnixNano() >= p.measurementStart && f.SYN.UnixNano() < p.measurementEnd {
			havePrimarySYN = true
		}
	}
	return havePrimarySYN
}

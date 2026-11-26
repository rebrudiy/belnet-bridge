// Command observer is the G03 bounded PCAP phase-window extractor.
// No TLS keys, application payloads or credentials are exported.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"
)

const ObserverVersion = "g04-header-observer-v1"

const (
	MaxFlows            = 512
	MaxPendingPerStream = 256 * 1024
	MaxPendingGlobal    = 8 * 1024 * 1024
	MaxPendingSegments  = 256
	MaxConsumedHistory  = GroupByteCap
	MaxPacket           = 1024 * 1024
	MaxSelected         = 64
	GroupByteCap        = 256 * 1024 * 1024
	MaxWindows          = 45
	DurationNS          = int64(2 * time.Second)
)

var offsets = []int64{0, int64(8 * time.Second), int64(18 * time.Second), int64(28 * time.Second)}

type Metadata struct {
	GroupID                string    `json:"group_id"`
	Split                  string    `json:"split"`
	Class                  string    `json:"class"`
	Profile                string    `json:"profile"`
	ServerPorts            []uint16  `json:"server_ports"`
	CaptureStarted         time.Time `json:"capture_started_utc"`
	CaptureEnded           time.Time `json:"capture_ended_utc"`
	CaptureCapBytes        int64     `json:"capture_cap_bytes"`
	CapHit                 bool      `json:"capture_cap_hit"`
	Dropped                *uint64   `json:"packets_dropped"`
	FreezeSHA              string    `json:"freeze_sha256"`
	MeasuredSeconds        int       `json:"measured_seconds"`
	MeasurementStartMicros int64     `json:"measurement_start_unix_micros,omitempty"`
	PrefixGraceSeconds     int       `json:"prefix_grace_seconds,omitempty"`
	WindowOffsetsSeconds   []int64   `json:"window_offsets_seconds,omitempty"`
}
type Event struct {
	RawNS     int64  `json:"raw_ns"`
	Ordinal   uint64 `json:"ordinal"`
	At        int64  `json:"at_micros"`
	Direction int    `json:"direction"`
	Bytes     int    `json:"bytes"`
}
type Tuple struct {
	ClientIP   string `json:"client_ip"`
	ClientPort uint16 `json:"client_port"`
	ServerIP   string `json:"server_ip"`
	ServerPort uint16 `json:"server_port"`
	Protocol   string `json:"protocol"`
}
type Window struct {
	orderLast          [2]int64
	orderHave          [2]bool
	OrderingAmbiguous  bool      `json:"ordering_ambiguous"`
	MaskedRules        []string  `json:"masked_rules"`
	AmbiguityReasons   []string  `json:"ordering_ambiguity_reasons"`
	ID                 string    `json:"session_id"`
	GroupID            string    `json:"group_id"`
	Split              string    `json:"split"`
	Class              string    `json:"class"`
	Profile            string    `json:"profile"`
	FlowID             string    `json:"flow_id"`
	Kind               string    `json:"window_kind"`
	Tuple              Tuple     `json:"five_tuple"`
	Start              time.Time `json:"window_start_utc"`
	End                time.Time `json:"window_end_utc"`
	Status             string    `json:"status"`
	Eligible           bool      `json:"eligible"`
	Primary            bool      `json:"primary"`
	Reasons            []string  `json:"coverage_reasons"`
	TotalRecords       uint64    `json:"total_records"`
	SelectionTruncated bool      `json:"feature_selection_truncated"`
	Events             []Event   `json:"events"`
	start              int64
	end                int64
}
type Flow struct {
	RawTCPPayloadBytes        uint64               `json:"raw_tcp_payload_bytes_including_retransmits"`
	HeaderEvidenceAbsent      bool                 `json:"header_evidence_absent"`
	TCPSequenceCensusComplete bool                 `json:"tcp_sequence_census_complete"`
	TLSHeaderParseValid       bool                 `json:"tls_header_parse_valid"`
	TLSHeaders                uint64               `json:"total_tls_record_headers"`
	PrimaryTLS23Headers       uint64               `json:"primary_tls23_headers"`
	Streams                   []StreamEvidence     `json:"tls_streams"`
	IssueTimestamps           map[string]time.Time `json:"issue_timestamps"`
	PrimaryScope              bool                 `json:"primary_scope"`
	SetupState                string               `json:"setup_state"`
	RSTCaptured               bool                 `json:"rst_captured"`
	FINCaptured               bool                 `json:"fin_captured"`
	lastPacketDirection       int
	lastRecordDirection       int
	streamRecordAt            [2]int64
	streamHaveRecord          [2]bool
	ID                        string     `json:"flow_id"`
	Tuple                     Tuple      `json:"five_tuple"`
	SYN                       *time.Time `json:"syn_utc"`
	SYNACK                    bool       `json:"syn_ack_captured"`
	First                     *time.Time `json:"first_tls23_header_available_utc"`
	Closed                    *time.Time `json:"closed_utc"`
	Windows                   []*Window  `json:"windows"`
	Retransmitted             uint64     `json:"retransmitted_bytes"`
	Records                   uint64     `json:"tls23_headers"`
	Issues                    []string   `json:"issues"`
	streams                   map[int]*Stream
	synBase                   uint32
	firstNS                   int64
	closedNS                  int64
	issueAt                   map[string]int64
	finMask                   int
	minPacketNS               int64
	lastPacketNS              int64
	havePacket                bool
	lastRecordNS              int64
	haveRecord                bool
}
type Report struct {
	long                     *collector
	CoverageSHA              string            `json:"coverage_semantics_sha256"`
	HeaderEvidenceAbsent     bool              `json:"header_evidence_absent"`
	EvidenceUnit             string            `json:"evidence_unit"`
	ConsumedHistoryHighWater int               `json:"consumed_history_bytes_high_water"`
	ZeroPayloadSetupOnly     bool              `json:"zero_payload_setup_only"`
	OrderingSHA              string            `json:"ordering_semantics_sha256"`
	Version                  string            `json:"version"`
	Schema                   int               `json:"schema"`
	Metadata                 Metadata          `json:"metadata"`
	Observer                 string            `json:"observer"`
	PCAPSHA                  string            `json:"pcap_sha256"`
	Limits                   map[string]int    `json:"limits"`
	Counters                 map[string]uint64 `json:"counters"`
	GroupAnchor              *time.Time        `json:"group_first_tls23_header_available_utc"`
	GroupWindows             []*Window         `json:"group_windows"`
	Flows                    []*Flow           `json:"flows"`
	Windows                  []*Window         `json:"windows"`
	Observations             []*Window         `json:"observations"`
	CoverageComplete         bool              `json:"coverage_complete"`
	GlobalReasons            []string          `json:"global_coverage_reasons"`
	PendingHighWater         int               `json:"pending_bytes_high_water"`
	SelectedHighWater        int               `json:"selected_event_high_water"`
	ClockDiagnostics         ClockDiagnostics  `json:"clock_diagnostics"`
	MeasurementStart         *time.Time        `json:"measurement_start_utc"`
	MeasurementEnd           *time.Time        `json:"measurement_end_utc"`
	DiagnosticObservations   []*Window         `json:"diagnostic_observations"`
	parser                   *Parser
}
type ClockDiagnostics struct {
	CrossDirectionPacketBackwards uint64        `json:"cross_direction_packet_backward_edges"`
	CrossDirectionRecordBackwards uint64        `json:"cross_direction_record_backward_edges"`
	FileBackwardEdges             uint64        `json:"file_order_backward_edges"`
	MaxFileBackwardNS             uint64        `json:"max_file_order_backward_ns"`
	CrossFlowBackwardEdges        uint64        `json:"cross_flow_backward_edges"`
	MaxCrossFlowBackwardNS        uint64        `json:"max_cross_flow_backward_ns"`
	UnattributedBackwardEdges     uint64        `json:"unattributed_backward_edges"`
	PerFlowBackwardEdges          uint64        `json:"per_flow_backward_edges"`
	MaxPerFlowBackwardNS          uint64        `json:"max_per_flow_backward_ns"`
	PerStreamBackwardEdges        uint64        `json:"per_stream_backward_edges"`
	MaxPerStreamBackwardNS        uint64        `json:"max_per_stream_backward_ns"`
	RecordCausalBackwardEdges     uint64        `json:"record_causal_backward_edges"`
	MaxRecordCausalBackwardNS     uint64        `json:"max_record_causal_backward_ns"`
	Samples                       []ClockSample `json:"samples"`
}
type ClockSample struct {
	PacketIndex  uint64 `json:"packet_index_zero_based"`
	PreviousNS   int64  `json:"previous_ns"`
	AtNS         int64  `json:"at_ns"`
	BackwardNS   uint64 `json:"backward_ns"`
	PreviousFlow string `json:"previous_flow"`
	Flow         string `json:"flow"`
}
type Parser struct {
	aggregates       *collector
	prefixAnchors    map[string]int64
	recordOrdinal    uint64
	meta             Metadata
	report           Report
	active           map[string]*Flow
	ports            map[uint16]bool
	pendingBytes     int
	historyBytes     int
	selected         int
	anchor           int64
	haveAnchor       bool
	previousPacket   int64
	previousFlow     string
	measurementStart int64
	measurementEnd   int64
	windowOffsetsNS  []int64
	discoveryOnly    bool
	fixedReady       bool
	firstPacket      int64
	lastPacket       int64
	seenPacket       bool
	global           []string
	maxGlobal        int
}
type Segment struct {
	data []byte
	at   int64
}
type Stream struct {
	base          uint32
	pos           uint32
	pending       map[uint32]Segment
	pendingBytes  int
	header        [5]byte
	headerN       int
	remaining     int
	recordSize    int
	kind          byte
	inRecord      bool
	bad           bool
	gapAt         int64
	flow          *Flow
	direction     int
	owner         *Parser
	availableNS   int64
	recordMaxNS   int64
	headerStartNS int64
	history       []byte
	finSeen       bool
	finOffset     uint32
	finAt         int64
	rstSeen       bool
	rstOffset     uint32
	rstAt         int64
	maxACK        uint32
	ackAt         int64
	lastPacketNS  int64
	minPacketNS   int64
	havePacket    bool
}

func utc(ns int64) time.Time { return time.Unix(0, ns).UTC() }
func addReason(reasons *[]string, reason string) {
	for _, r := range *reasons {
		if r == reason {
			return
		}
	}
	*reasons = append(*reasons, reason)
}
func (f *Flow) issue(reason string, at int64) {
	if _, ok := f.issueAt[reason]; !ok {
		f.issueAt[reason] = at
		f.Issues = append(f.Issues, reason)
	} else if at < f.issueAt[reason] {
		// Repeated causal faults may arrive later in file order with earlier raw time.
		f.issueAt[reason] = at
	}
}
func newParser(meta Metadata) (*Parser, error) {
	if meta.GroupID == "" || meta.Profile == "" || (meta.Split != "train" && meta.Split != "validation" && meta.Split != "test" && meta.Split != "development") || (meta.Class != "benign" && meta.Class != "belnet") {
		return nil, fmt.Errorf("group_id/profile, valid split/class required")
	}
	if len(meta.ServerPorts) == 0 {
		meta.ServerPorts = []uint16{443, 19443}
	}
	if meta.CaptureCapBytes == 0 {
		meta.CaptureCapBytes = GroupByteCap
	}
	if meta.MeasuredSeconds == 0 {
		meta.MeasuredSeconds = 45
	}
	if meta.MeasuredSeconds < 2 || meta.MeasuredSeconds > 90 {
		return nil, fmt.Errorf("G03 measured_seconds must be2..90; capture grace is separate")
	}
	if meta.MeasurementStartMicros < 0 || meta.MeasurementStartMicros > (1<<63-1)/1000 {
		return nil, fmt.Errorf("measurement_start_unix_micros must be a positive VM UTC value when supplied")
	}
	if meta.PrefixGraceSeconds < 0 || meta.PrefixGraceSeconds > 2 {
		return nil, fmt.Errorf("prefix_grace_seconds must be0..2")
	}
	if meta.CaptureCapBytes < 24 || meta.CaptureCapBytes > GroupByteCap {
		return nil, fmt.Errorf("capture cap must be24..256MiB")
	}
	p := &Parser{meta: meta, active: map[string]*Flow{}, ports: map[uint16]bool{}, maxGlobal: MaxPendingGlobal}
	if len(meta.WindowOffsetsSeconds) == 0 {
		for _, offset := range offsets {
			p.windowOffsetsNS = append(p.windowOffsetsNS, offset)
		}
	} else {
		if len(meta.WindowOffsetsSeconds) > MaxWindows {
			return nil, fmt.Errorf("at most%d fixed windows", MaxWindows)
		}
		previous := int64(-1)
		for _, offset := range meta.WindowOffsetsSeconds {
			if offset < 0 || offset <= previous || offset > int64(meta.MeasuredSeconds)-2 {
				return nil, fmt.Errorf("window offsets must be unique increasing nonnegative seconds, with full2s inside measurement")
			}
			p.windowOffsetsNS = append(p.windowOffsetsNS, offset*int64(time.Second))
			previous = offset
		}
	}
	for _, offset := range p.windowOffsetsNS {
		if offset+DurationNS > int64(meta.MeasuredSeconds)*int64(time.Second) {
			return nil, fmt.Errorf("default windows require at least30s; declare window_offsets_seconds for shorter horizons")
		}
	}
	for _, port := range meta.ServerPorts {
		p.ports[port] = true
	}
	p.report = Report{CoverageSHA: CoverageSemanticsSHA, OrderingSHA: OrderingSemanticsSHA, Version: ObserverVersion, Schema: 6, EvidenceUnit: "tls23_header_declared_length", Metadata: meta, Observer: "G04 SHADOW: TLS23 declared length at5-byte-header availability=max header/prefix timestamps; body is not required; source file order preserved; two-pass earliest selection is not an online policy", Limits: map[string]int{"flows": MaxFlows, "pending_per_stream_bytes": MaxPendingPerStream, "pending_global_bytes": MaxPendingGlobal, "pending_segments_per_stream": MaxPendingSegments, "selected_records_per_window": MaxSelected, "max_packet_bytes": MaxPacket, "max_windows": MaxWindows, "max_measured_seconds": 90, "consumed_history_logical_bytes_per_pass": MaxConsumedHistory}, Counters: map[string]uint64{}, GroupWindows: []*Window{}, Flows: []*Flow{}, Windows: []*Window{}, Observations: []*Window{}, ClockDiagnostics: ClockDiagnostics{Samples: []ClockSample{}}, DiagnosticObservations: []*Window{}, parser: p}
	if meta.CaptureStarted.IsZero() || meta.CaptureEnded.IsZero() || !meta.CaptureEnded.After(meta.CaptureStarted) || meta.Dropped == nil {
		addReason(&p.global, "capture_metadata_missing")
	}
	if meta.CapHit {
		addReason(&p.global, "byte_censored")
	}
	if meta.Dropped != nil && *meta.Dropped > 0 {
		addReason(&p.global, "capture_packet_drops")
	}
	if meta.MeasurementStartMicros != 0 {
		p.measurementStart = meta.MeasurementStartMicros * 1000
	} else {
		p.measurementStart = meta.CaptureStarted.UnixNano()
	}
	if p.measurementStart > (1<<63-1)-int64(92*time.Second) {
		return nil, fmt.Errorf("measurement interval overflows")
	}
	p.measurementEnd = p.measurementStart + int64(meta.MeasuredSeconds)*int64(time.Second)
	ms, me := utc(p.measurementStart), utc(p.measurementEnd)
	p.report.MeasurementStart, p.report.MeasurementEnd = &ms, &me
	if meta.MeasurementStartMicros != 0 {
		p.initGroupWindows(p.measurementStart)
	}
	p.aggregates = newCollector(p.measurementStart, p.measurementEnd)
	return p, nil
}
func (p *Parser) window(flow *Flow, kind string, start int64, index int) *Window {
	id := fmt.Sprintf("%s/%s/%s-%d", p.meta.GroupID, flow.ID, kind, index)
	w := &Window{ID: id, GroupID: p.meta.GroupID, Split: p.meta.Split, Class: p.meta.Class, Profile: p.meta.Profile, FlowID: flow.ID, Kind: kind, Tuple: flow.Tuple, Start: utc(start), End: utc(start + DurationNS), Events: []Event{}, Reasons: []string{}, Primary: kind != "bootstrap-prefix", start: start, end: start + DurationNS}
	flow.Windows = append(flow.Windows, w)
	return w
}
func (p *Parser) fixedKind() string {
	if p.meta.MeasurementStartMicros != 0 {
		return "phase_fixed"
	}
	return "group-fixed"
}
func (p *Parser) initGroupWindows(anchor int64) {
	if p.fixedReady || p.discoveryOnly {
		return
	}
	p.fixedReady = true
	for _, f := range p.report.Flows {
		p.fixed(f)
	}
	for i, off := range p.windowOffsetsNS {
		w := &Window{ID: fmt.Sprintf("%s/%s-%d", p.meta.GroupID, p.fixedKind(), i), GroupID: p.meta.GroupID, Split: p.meta.Split, Class: p.meta.Class, Profile: p.meta.Profile,
			Kind: "group-coverage", Start: utc(anchor + off), End: utc(anchor + off + DurationNS), Events: []Event{}, Reasons: []string{}, Primary: true, start: anchor + off, end: anchor + off + DurationNS}
		p.report.GroupWindows = append(p.report.GroupWindows, w)
	}
}
func (p *Parser) fixed(flow *Flow) {
	if !p.fixedReady || p.discoveryOnly {
		return
	}
	anchor := p.anchor
	if p.meta.MeasurementStartMicros != 0 {
		anchor = p.measurementStart
	}
	for i, offset := range p.windowOffsetsNS {
		p.window(flow, p.fixedKind(), anchor+offset, i)
	}
}
func (p *Parser) event(flow *Flow, direction, size int, at int64) {
	if !p.haveAnchor || at < p.anchor {
		p.haveAnchor = true
		p.anchor = at
		t := utc(at)
		p.report.GroupAnchor = &t
	}
	index := 0
	if direction == -1 {
		index = 1
	}
	if flow.streamHaveRecord[index] && at < flow.streamRecordAt[index] {
		d := uint64(flow.streamRecordAt[index] - at)
		p.report.ClockDiagnostics.RecordCausalBackwardEdges++
		p.report.ClockDiagnostics.MaxRecordCausalBackwardNS = max(p.report.ClockDiagnostics.MaxRecordCausalBackwardNS, d)
		flow.issue("record_stream_causal_time_reversal", at)
	}
	if flow.haveRecord && flow.lastRecordDirection != direction && at < flow.lastRecordNS {
		p.report.ClockDiagnostics.CrossDirectionRecordBackwards++
	}
	flow.streamHaveRecord[index] = true
	flow.streamRecordAt[index] = at
	flow.lastRecordNS = at
	flow.haveRecord = true
	flow.lastRecordDirection = direction
	if flow.First != nil && at < flow.firstNS {
		t := utc(at)
		flow.First = &t
		flow.firstNS = at
	}
	if flow.First == nil {
		t := utc(at)
		flow.First = &t
		flow.firstNS = at
		if !p.discoveryOnly {
			kind := "flow-prefix"
			if p.meta.MeasurementStartMicros != 0 && at < p.measurementStart {
				kind = "bootstrap-prefix"
			}
			p.window(flow, kind, at, 0)
		}
	}
	flow.Records++
	if at >= p.measurementStart && at < p.measurementEnd {
		flow.PrimaryTLS23Headers++
	}
	if p.discoveryOnly {
		return
	}
	if p.aggregates != nil {
		p.aggregates.record(flow.ID, direction, size, at)
	}
	p.recordOrdinal++
	for _, w := range flow.Windows {
		if at >= w.start && at < w.end {
			w.TotalRecords++
			e := Event{RawNS: at, Ordinal: p.recordOrdinal, At: (at - w.start) / 1000, Direction: direction, Bytes: size}
			observeOrdering(w, e)
			grew := selectEarliest(w, e)
			if grew {
				p.selected++
				p.report.SelectedHighWater = max(p.report.SelectedHighWater, p.selected)
			}
		}
	}
	for _, w := range p.report.GroupWindows {
		if at >= w.start && at < w.end {
			w.TotalRecords++
		}
	}
}
func (s *Stream) release() {
	s.owner.pendingBytes -= s.pendingBytes
	s.pendingBytes = 0
	s.pending = map[uint32]Segment{}
}
func (s *Stream) fail(reason string, at int64) { s.bad = true; s.flow.issue(reason, at); s.release() }
func (s *Stream) consume(data []byte, at int64) {
	for len(data) > 0 && !s.bad {
		s.recordMaxNS = max(s.recordMaxNS, at)
		if !s.inRecord {
			if s.headerN == 0 {
				s.headerStartNS = at
			}
			n := min(5-s.headerN, len(data))
			copy(s.header[s.headerN:], data[:n])
			s.headerN += n
			data = data[n:]
			if (s.headerN >= 1 && (s.header[0] < 20 || s.header[0] > 24)) || (s.headerN >= 2 && s.header[1] != 3) || (s.headerN >= 3 && s.header[2] > 4) {
				s.fail("malformed_tls", at)
				return
			}
			if s.headerN < 5 {
				return
			}
			if s.header[0] < 20 || s.header[0] > 24 || s.header[1] != 3 || s.header[2] > 4 {
				s.fail("malformed_tls", at)
				return
			}
			s.kind = s.header[0]
			s.remaining = int(binary.BigEndian.Uint16(s.header[3:5]))
			s.recordSize = s.remaining + 5
			s.inRecord = true
			s.flow.TLSHeaders++
			if s.kind == 23 {
				s.owner.event(s.flow, s.direction, s.recordSize, s.recordMaxNS)
			}
		}
		n := min(s.remaining, len(data))
		s.remaining -= n
		data = data[n:]
		if s.remaining == 0 {
			s.headerN = 0
			s.inRecord = false
			s.recordMaxNS = 0
		}
	}
}
func (s *Stream) feed(seq uint32, data []byte, at int64) {
	if len(data) == 0 || s.bad {
		return
	}
	offset := seq - s.base
	if offset > 0x7fffffff {
		return
	}
	if offset < s.pos {
		skip := min(int(s.pos-offset), len(data))
		for i := 0; i < skip; i++ {
			if int(offset)+i >= len(s.history) || s.history[int(offset)+i] != data[i] {
				s.fail("tcp_overlap_conflict", at)
				return
			}
		}
		s.flow.Retransmitted += uint64(skip)
		offset += uint32(skip)
		data = data[skip:]
	}
	if len(data) == 0 {
		return
	}
	// Validate cached overlap even when this segment fills the current gap.
	for prior, old := range s.pending {
		lo := max(prior, offset)
		hi := min(uint64(prior)+uint64(len(old.data)), uint64(offset)+uint64(len(data)))
		for i := uint64(lo); i < hi; i++ {
			if old.data[i-uint64(prior)] != data[i-uint64(offset)] {
				s.fail("tcp_overlap_conflict", at)
				return
			}
		}
	}
	if offset == s.pos {
		s.availableNS = max(s.availableNS, at)
		if !s.remember(data, at) {
			return
		}
		s.consume(data, s.availableNS)
		s.pos += uint32(len(data))
	} else {
		for prior, old := range s.pending {
			lo := max(prior, offset)
			hi := min(uint64(prior)+uint64(len(old.data)), uint64(offset)+uint64(len(data)))
			if uint64(lo) < hi {
				for i := uint64(lo); i < hi; i++ {
					if old.data[i-uint64(prior)] != data[i-uint64(offset)] {
						s.fail("tcp_overlap_conflict", at)
						return
					}
				}
			}
		}
		if prior, ok := s.pending[offset]; ok && len(prior.data) >= len(data) {
			s.flow.Retransmitted += uint64(len(data))
			return
		}
		if len(s.pending) >= MaxPendingSegments {
			s.fail("reassembly_count_censored", at)
			return
		}
		if s.pendingBytes+len(data) > MaxPendingPerStream || s.owner.pendingBytes+len(data) > s.owner.maxGlobal {
			s.fail("reassembly_byte_censored", at)
			return
		}
		if old, ok := s.pending[offset]; ok {
			s.pendingBytes -= len(old.data)
			s.owner.pendingBytes -= len(old.data)
		}
		arrival := at
		if old, ok := s.pending[offset]; ok {
			arrival = max(arrival, old.at)
		}
		s.pending[offset] = Segment{data: append([]byte(nil), data...), at: arrival}
		s.pendingBytes += len(data)
		s.owner.pendingBytes += len(data)
		if s.owner.pendingBytes > s.owner.report.PendingHighWater {
			s.owner.report.PendingHighWater = s.owner.pendingBytes
		}
		if s.gapAt == 0 {
			s.gapAt = at
		}
	}
	for len(s.pending) > 0 && !s.bad {
		var first uint32
		have := false
		for off := range s.pending {
			if !have || off < first {
				first = off
				have = true
			}
		}
		if first > s.pos {
			break
		}
		segment := s.pending[first]
		delete(s.pending, first)
		s.pendingBytes -= len(segment.data)
		s.owner.pendingBytes -= len(segment.data)
		skip := min(int(s.pos-first), len(segment.data))
		for i := 0; i < skip; i++ {
			if int(first)+i >= len(s.history) || s.history[int(first)+i] != segment.data[i] {
				s.fail("tcp_overlap_conflict", at)
				return
			}
		}
		s.flow.Retransmitted += uint64(skip)
		segment.data = segment.data[skip:]
		s.availableNS = max(s.availableNS, max(at, segment.at))
		if !s.remember(segment.data, at) {
			return
		}
		s.consume(segment.data, s.availableNS)
		s.pos += uint32(len(segment.data))
	}
	if len(s.pending) == 0 {
		s.gapAt = 0
	}
}
func tupleKey(t Tuple) string {
	return net.JoinHostPort(t.ClientIP, fmt.Sprint(t.ClientPort)) + ">" + net.JoinHostPort(t.ServerIP, fmt.Sprint(t.ServerPort))
}
func (p *Parser) newFlow(t Tuple, syn bool, base uint32, at int64) *Flow {
	if len(p.report.Flows) >= MaxFlows {
		addReason(&p.global, "flow_count_censored")
		p.report.Counters["flows_rejected_at_cap"]++
		return nil
	}
	f := &Flow{ID: fmt.Sprintf("flow-%04d", len(p.report.Flows)), Tuple: t, Windows: []*Window{}, Issues: []string{}, streams: map[int]*Stream{}, issueAt: map[string]int64{}, synBase: base}
	if syn {
		x := utc(at)
		f.SYN = &x
		f.streams[1] = &Stream{base: base, pending: map[uint32]Segment{}, flow: f, direction: 1, owner: p}
	} else {
		f.issue("missing_syn", at)
	}
	p.active[tupleKey(t)] = f
	p.report.Flows = append(p.report.Flows, f)
	p.fixed(f)
	if at, ok := p.prefixAnchors[f.ID]; ok {
		t := utc(at)
		f.First = &t
		f.firstNS = at
		kind := "flow-prefix"
		if p.meta.MeasurementStartMicros != 0 && at < p.measurementStart {
			kind = "bootstrap-prefix"
		}
		p.window(f, kind, at, 0)
	}
	return f
}
func (p *Parser) packet(packet []byte, link uint32, at int64) {
	p.report.Counters["packets"]++
	previousAt, previousFlow := p.previousPacket, p.previousFlow
	backward := p.seenPacket && at < previousAt
	if backward {
		d := uint64(previousAt - at)
		p.report.ClockDiagnostics.FileBackwardEdges++
		p.report.ClockDiagnostics.MaxFileBackwardNS = max(p.report.ClockDiagnostics.MaxFileBackwardNS, d)
	}
	currentFlow := ""
	defer func() {
		if backward {
			d := uint64(previousAt - at)
			if currentFlow != "" && previousFlow != "" && currentFlow != previousFlow {
				p.report.ClockDiagnostics.CrossFlowBackwardEdges++
				p.report.ClockDiagnostics.MaxCrossFlowBackwardNS = max(p.report.ClockDiagnostics.MaxCrossFlowBackwardNS, d)
			} else if currentFlow == "" || previousFlow == "" {
				p.report.ClockDiagnostics.UnattributedBackwardEdges++
			}
			if len(p.report.ClockDiagnostics.Samples) < 32 {
				p.report.ClockDiagnostics.Samples = append(p.report.ClockDiagnostics.Samples, ClockSample{p.report.Counters["packets"] - 1, previousAt, at, d, previousFlow, currentFlow})
			}
		}
		p.previousFlow = currentFlow
	}()
	if !p.seenPacket {
		p.firstPacket = at
		p.seenPacket = true
	} else {
		p.firstPacket = min(p.firstPacket, at)
	}
	p.lastPacket = max(p.lastPacket, at)
	p.previousPacket = at
	ip := packet
	switch link {
	case 1:
		if len(packet) < 14 {
			return
		}
		kind := binary.BigEndian.Uint16(packet[12:14])
		offset := 14
		for kind == 0x8100 || kind == 0x88a8 {
			if len(packet) < offset+4 {
				return
			}
			kind = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += 4
		}
		if kind != 0x0800 && kind != 0x86dd {
			return
		}
		ip = packet[offset:]
	case 113:
		if len(packet) < 16 {
			return
		}
		ip = packet[16:]
	case 276:
		if len(packet) < 20 {
			return
		}
		ip = packet[20:]
	case 101:
	default:
		addReason(&p.global, "unsupported_link_type")
		return
	}
	if len(ip) < 1 {
		return
	}
	var src, dst string
	var tcp []byte
	if ip[0]>>4 == 4 {
		if len(ip) < 20 {
			return
		}
		ihl := int(ip[0]&15) * 4
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if ihl < 20 || total < ihl || total > len(ip) {
			addReason(&p.global, "truncated_or_invalid_ip")
			return
		}
		if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
			addReason(&p.global, "ip_fragment_unreassembled")
			return
		}
		if ip[9] != 6 {
			p.report.Counters["non_tcp"]++
			return
		}
		src, dst = net.IP(ip[12:16]).String(), net.IP(ip[16:20]).String()
		tcp = ip[ihl:total]
	} else if ip[0]>>4 == 6 {
		if len(ip) < 40 {
			return
		}
		total := 40 + int(binary.BigEndian.Uint16(ip[4:6]))
		if total > len(ip) {
			addReason(&p.global, "truncated_or_invalid_ip")
			return
		}
		next, offset := ip[6], 40
		for next == 0 || next == 43 || next == 60 {
			if offset+2 > total {
				addReason(&p.global, "invalid_ipv6_extension")
				return
			}
			n := (int(ip[offset+1]) + 1) * 8
			next = ip[offset]
			offset += n
			if offset > total {
				addReason(&p.global, "invalid_ipv6_extension")
				return
			}
		}
		if next == 44 {
			addReason(&p.global, "ip_fragment_unreassembled")
			return
		}
		if next != 6 {
			p.report.Counters["non_tcp"]++
			return
		}
		src, dst = net.IP(ip[8:24]).String(), net.IP(ip[24:40]).String()
		tcp = ip[offset:total]
	} else {
		return
	}
	if len(tcp) < 20 {
		addReason(&p.global, "truncated_tcp")
		return
	}
	sport, dport := binary.BigEndian.Uint16(tcp[:2]), binary.BigEndian.Uint16(tcp[2:4])
	direction := 1
	t := Tuple{src, sport, dst, dport, "tcp"}
	if !p.ports[dport] {
		if !p.ports[sport] {
			p.report.Counters["other_tcp"]++
			return
		}
		direction = -1
		t = Tuple{dst, dport, src, sport, "tcp"}
	}
	p.report.Counters["selected_tcp_packets"]++
	off := int(tcp[12]>>4) * 4
	if off < 20 || off > len(tcp) {
		addReason(&p.global, "truncated_tcp")
		return
	}
	p.report.Counters["selected_ip_bytes"] += uint64(len(ip))
	if direction == 1 {
		p.report.Counters["tcp_ciphertext_bytes_up_including_retransmits"] += uint64(len(tcp) - off)
	} else {
		p.report.Counters["tcp_ciphertext_bytes_down_including_retransmits"] += uint64(len(tcp) - off)
	}
	seq := binary.BigEndian.Uint32(tcp[4:8])
	flags := tcp[13]
	syn := flags&2 != 0
	ack := flags&16 != 0
	key := tupleKey(t)
	f := p.active[key]
	if syn && direction == 1 && !ack {
		if f == nil || f.SYN == nil || f.synBase != seq+1 {
			if f != nil {
				for _, s := range f.streams {
					if len(s.pending) > 0 {
						f.issue("tcp_reassembly_gap", s.gapAt)
					}
					if !s.inRecord && s.headerN > 0 {
						f.issue("partial_final_tls_header", s.headerStartNS)
					}
					s.release()
				}
				if f.Closed == nil {
					closed := utc(at)
					f.Closed = &closed
					f.closedNS = at
				}
			}
			f = p.newFlow(t, true, seq+1, at)
		}
	} else if f == nil {
		f = p.newFlow(t, false, 0, at)
	}
	if f == nil {
		return
	}
	// Count raw payload before ALL SYN/handshake/stream branches, including TFO.
	f.RawTCPPayloadBytes += uint64(len(tcp) - off)
	f.RSTCaptured = f.RSTCaptured || flags&4 != 0
	f.FINCaptured = f.FINCaptured || flags&1 != 0
	currentFlow = f.ID
	if f.havePacket && at < f.lastPacketNS {
		d := uint64(f.lastPacketNS - at)
		p.report.ClockDiagnostics.PerFlowBackwardEdges++
		p.report.ClockDiagnostics.MaxPerFlowBackwardNS = max(p.report.ClockDiagnostics.MaxPerFlowBackwardNS, d)
		if f.lastPacketDirection != direction {
			p.report.ClockDiagnostics.CrossDirectionPacketBackwards++
		}
	}
	if !f.havePacket {
		f.minPacketNS = at
	} else {
		f.minPacketNS = min(f.minPacketNS, at)
	}
	f.havePacket = true
	f.lastPacketNS = at
	f.lastPacketDirection = direction
	if syn && direction == -1 {
		if old := f.streams[-1]; old != nil && old.base != seq+1 {
			f.issue("conflicting_syn_ack", at)
		} else if old == nil {
			f.streams[-1] = &Stream{base: seq + 1, pending: map[uint32]Segment{}, flow: f, direction: -1, owner: p}
			f.SYNACK = true
		}
	}
	if s := f.streams[direction]; s != nil {
		if s.havePacket && at < s.lastPacketNS {
			d := uint64(s.lastPacketNS - at)
			p.report.ClockDiagnostics.PerStreamBackwardEdges++
			p.report.ClockDiagnostics.MaxPerStreamBackwardNS = max(p.report.ClockDiagnostics.MaxPerStreamBackwardNS, d)
			f.issue("non_monotonic_stream_clock", at)
		}
		s.havePacket = true
		s.lastPacketNS = at
		s.feed(seq+func() uint32 {
			if syn {
				return 1
			}
			return 0
		}(), tcp[off:], at)
	}
	if ack {
		if peer := f.streams[-direction]; peer != nil {
			peer.observeACK(binary.BigEndian.Uint32(tcp[8:12]), at)
		}
	}
	if s := f.streams[direction]; s != nil {
		dataEnd := seq + uint32(len(tcp)-off)
		if syn {
			dataEnd++
		}
		if flags&1 != 0 {
			s.observeClose(dataEnd, at, false)
		}
		if flags&4 != 0 {
			s.observeClose(dataEnd, at, true)
		}
	}
	if flags&1 != 0 {
		if direction == 1 {
			f.finMask |= 1
		} else {
			f.finMask |= 2
		}
	}
	if (flags&4 != 0 || f.finMask == 3) && f.Closed == nil {
		x := utc(at)
		f.Closed = &x
		f.closedNS = at
	}
}

// Both anchor modes use a bounded discovery pass for true per-flow prefix
// minima before assigning windows. No packet sorting or payload spooling.
func (p *Parser) read(reader io.Reader) error {
	seek, ok := reader.(io.ReadSeeker)
	if !ok {
		return fmt.Errorf("V2 requires seekable PCAP for bounded exact per-flow minimum prefix anchors")
	}
	origin, err := seek.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	discovery, err := newParser(p.meta)
	if err != nil {
		return err
	}
	discovery.discoveryOnly = true
	if err = discovery.readPackets(reader); err != nil {
		return err
	}
	if _, err = seek.Seek(origin, io.SeekStart); err != nil {
		return err
	}
	p.prefixAnchors = map[string]int64{}
	for _, flow := range discovery.report.Flows {
		if flow.First != nil {
			p.prefixAnchors[flow.ID] = flow.firstNS
		}
	}
	if discovery.haveAnchor {
		p.haveAnchor = true
		p.anchor = discovery.anchor
		t := utc(p.anchor)
		p.report.GroupAnchor = &t
		if !p.fixedReady {
			p.initGroupWindows(p.anchor)
		}
	}
	return p.readPackets(reader)
}
func (p *Parser) readPackets(reader io.Reader) error {
	r := bufio.NewReaderSize(reader, 128*1024)
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("PCAP header: %w", err)
	}
	var order binary.ByteOrder
	nano := false
	switch hex.EncodeToString(header[:4]) {
	case "d4c3b2a1":
		order = binary.LittleEndian
	case "a1b2c3d4":
		order = binary.BigEndian
	case "4d3cb2a1":
		order = binary.LittleEndian
		nano = true
	case "a1b23c4d":
		order = binary.BigEndian
		nano = true
	default:
		return fmt.Errorf("classic PCAP required, unsupported magic")
	}
	link := order.Uint32(header[20:24])
	if nano {
		p.report.Counters["pcap_timestamp_resolution_ns"] = 1
	} else {
		p.report.Counters["pcap_timestamp_resolution_ns"] = 1000
	}
	if link != 1 && link != 101 && link != 113 && link != 276 {
		return fmt.Errorf("unsupported PCAP linktype%d", link)
	}
	readBytes := int64(24)
	for {
		h := make([]byte, 16)
		n, err := io.ReadFull(r, h)
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil {
			addReason(&p.global, "truncated_pcap")
			break
		}
		caplen, original := order.Uint32(h[8:12]), order.Uint32(h[12:16])
		if caplen > MaxPacket {
			addReason(&p.global, "packet_byte_censored")
			break
		}
		readBytes += 16 + int64(caplen)
		if readBytes > p.meta.CaptureCapBytes {
			addReason(&p.global, "byte_censored")
			break
		}
		packet := make([]byte, caplen)
		if _, err := io.ReadFull(r, packet); err != nil {
			addReason(&p.global, "truncated_pcap")
			break
		}
		if caplen < original {
			addReason(&p.global, "packet_snaplen_censored")
		}
		sec, fraction := int64(order.Uint32(h[:4])), int64(order.Uint32(h[4:8]))
		if nano {
			if fraction >= 1_000_000_000 {
				return fmt.Errorf("invalid nanosecond timestamp")
			}
		} else {
			if fraction >= 1_000_000 {
				return fmt.Errorf("invalid microsecond timestamp")
			}
			fraction *= 1000
		}
		p.packet(packet, link, sec*1_000_000_000+fraction)
	}
	p.report.Counters["pcap_bytes_processed"] = uint64(readBytes)
	return nil
}
func reasonStatus(reasons []string, records uint64) string {
	if len(reasons) == 0 {
		if records == 0 {
			return "sparse"
		}
		return "complete"
	}
	for _, r := range reasons {
		if r == "byte_censored" || r == "packet_byte_censored" || r == "packet_snaplen_censored" || r == "reassembly_byte_censored" {
			return "byte_censored"
		}
		if r == "flow_count_censored" || r == "reassembly_count_censored" {
			return "count_censored"
		}
		if r == "missing_syn" || r == "missing_syn_ack" {
			return "missing_syn"
		}
		if r == "malformed_tls" || r == "tcp_overlap_conflict" {
			return "malformed"
		}
	}
	return "incomplete"
}
func (p *Parser) finalize() Report {
	if !p.seenPacket {
		addReason(&p.global, "no_packets")
	}
	if !p.meta.CaptureStarted.IsZero() && p.seenPacket && (p.firstPacket < p.meta.CaptureStarted.UnixNano() || p.lastPacket > p.meta.CaptureEnded.UnixNano()) {
		addReason(&p.global, "capture_clock_outside_metadata_bounds")
	}
	if p.meta.MeasurementStartMicros != 0 && (p.meta.CaptureStarted.UnixNano() > p.measurementStart || p.meta.CaptureEnded.UnixNano() < p.measurementEnd) {
		addReason(&p.global, "measurement_not_fully_captured")
	}
	for _, f := range p.report.Flows {
		p.classifySetup(f)
		if f.SYN != nil && !f.SYNACK && f.RawTCPPayloadBytes != 0 {
			f.issue("missing_syn_ack", f.SYN.UnixNano())
		}
		for _, s := range f.streams {
			if len(s.pending) > 0 {
				f.issue("tcp_reassembly_gap", s.gapAt)
			}
			s.finalizeCensus()
		}
	}
	p.finalizeHeaderEvidence()
	p.report.ZeroPayloadSetupOnly = p.zeroPayloadSetupOnly()
	p.report.HeaderEvidenceAbsent = p.headerEvidenceAbsent()
	if !p.haveAnchor && !p.report.ZeroPayloadSetupOnly && !p.report.HeaderEvidenceAbsent {
		addReason(&p.global, "no_tls23_group_anchor")
	}
	primaryReasons := p.primaryFlowCoverageReasons()
	for _, f := range p.report.Flows {
		for _, w := range f.Windows {
			for _, r := range p.global {
				addReason(&w.Reasons, r)
			}
			for reason, at := range f.issueAt {
				if at < w.end {
					addReason(&w.Reasons, reason)
				}
			}
			if p.meta.CaptureStarted.IsZero() || p.meta.CaptureEnded.IsZero() || w.start < p.meta.CaptureStarted.UnixNano() || w.end > p.meta.CaptureEnded.UnixNano() {
				addReason(&w.Reasons, "window_not_fully_captured")
			}
			sort.Strings(w.Reasons)
			w.Status = reasonStatus(w.Reasons, w.TotalRecords)
			if (w.Kind == "group-fixed" || w.Kind == "phase_fixed") && ((f.First != nil && f.firstNS >= w.end) || (f.havePacket && f.minPacketNS >= w.end) || (f.closedNS != 0 && f.closedNS < w.start)) {
				w.Status = "not_applicable"
				w.Eligible = false
			} else if w.Kind == "flow-prefix" && w.start >= p.measurementEnd {
				// Capture grace completes prefixes started during the measured
				// scope; it must not create an endless tail of new obligations.
				w.Status = "not_applicable"
				w.Eligible = false
				w.Primary = false
			} else {
				w.Eligible = len(w.Reasons) == 0
			}
			if w.Kind == "bootstrap-prefix" {
				w.Primary = false
			}
			if w.Kind == "flow-prefix" && w.Status != "not_applicable" && w.end > p.measurementEnd+int64(p.meta.PrefixGraceSeconds)*int64(time.Second) {
				addReason(&w.Reasons, "prefix_exceeds_declared_grace")
				w.Status = reasonStatus(w.Reasons, w.TotalRecords)
				w.Eligible = false
			}
			annotateOrdering(w)
			w.SelectionTruncated = w.TotalRecords > MaxSelected
			p.report.Windows = append(p.report.Windows, w)
			if w.Eligible && w.Primary {
				p.report.Observations = append(p.report.Observations, w)
			}
			if w.Kind == "bootstrap-prefix" {
				p.report.DiagnosticObservations = append(p.report.DiagnosticObservations, w)
			}
		}
	}
	for _, w := range p.report.GroupWindows {
		w.Reasons = append(w.Reasons, p.global...)
		if w.end > p.meta.CaptureEnded.UnixNano() || w.start < p.meta.CaptureStarted.UnixNano() {
			addReason(&w.Reasons, "window_not_fully_captured")
		}
		for _, f := range p.report.Flows {
			if f.havePacket && f.minPacketNS >= w.end {
				continue
			}
			for reason, at := range f.issueAt {
				if at < w.end && (f.closedNS == 0 || f.closedNS >= w.start) {
					addReason(&w.Reasons, reason)
				}
			}
		}
		sort.Strings(w.Reasons)
		annotateOrdering(w)
		w.Status = reasonStatus(w.Reasons, w.TotalRecords)
		w.Eligible = len(w.Reasons) == 0
	}
	p.report.GlobalReasons = append([]string{}, p.global...)
	for _, reason := range primaryReasons {
		addReason(&p.report.GlobalReasons, reason)
	}
	sort.Strings(p.report.GlobalReasons)
	p.report.CoverageComplete = len(p.report.GlobalReasons) == 0 && len(p.report.GroupWindows) == len(p.windowOffsetsNS)
	for _, w := range p.report.GroupWindows {
		p.report.CoverageComplete = p.report.CoverageComplete && w.Eligible
	}
	for _, w := range p.report.Windows {
		if w.Kind == "flow-prefix" && w.Status != "not_applicable" && !w.Eligible {
			p.report.CoverageComplete = false
		}
	}
	return p.report
}
func extract(path string, meta Metadata) (Report, error) {
	p, err := newParser(meta)
	if err != nil {
		return Report{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Report{}, err
	}
	err = p.read(file)
	if err != nil {
		return Report{}, err
	}
	pcapSHA := ""
	if info.Size() <= GroupByteCap {
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return Report{}, err
		}
		hash := sha256.New()
		copied, copyErr := io.Copy(hash, io.LimitReader(file, GroupByteCap+1))
		if copyErr != nil {
			err = copyErr
			return Report{}, err
		}
		after, statErr := file.Stat()
		if statErr != nil {
			return Report{}, statErr
		}
		if copied != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			addReason(&p.global, "capture_modified_during_extraction")
		} else {
			pcapSHA = hex.EncodeToString(hash.Sum(nil))
		}
	} else {
		// Never mislabel a prefix digest as the SHA256 of an oversized capture.
		addReason(&p.global, "byte_censored")
	}
	report := p.finalize()
	report.PCAPSHA = pcapSHA
	report.long = p.aggregates
	return report, nil
}

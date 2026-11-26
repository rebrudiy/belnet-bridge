package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

type featureDefinition struct {
	ID         string `json:"id"`
	Definition string `json:"definition"`
	Minimum    string `json:"minimum_evidence"`
}

var featureDefinitions = []featureDefinition{
	{"lf01_exact26_share", "TLS23 headers with declared record length26 bytes / all TLS23 headers available inside primary80s", "16 headers"},
	{"lf02_tiny_le64_share", "TLS23 headers with declared record length<=64 bytes / all TLS23 headers available inside primary80s", "16 headers"},
	{"lf03_length_concentration", "1 - exact Shannon declared-header-length entropy / log2(header count); censored histogram abstains", "16 headers; exact uncensored declared-length histogram"},
	{"lf04_duplex_byte_balance", "1-abs(upDeclaredTLSbytes-downDeclaredTLSbytes)/(upDeclaredTLSbytes+downDeclaredTLSbytes); lengths observed at header availability, not delivered bytes", "16 headers and4 in each direction"},
	{"lf05_immediate_reply_share", "within-flow uplink header availability immediately followed by downlink header availability within0..10ms / uplink headers; no cross-flow pairing", "16 headers and8 uplink; unambiguous header cross-direction order including raw/projected ties; no negative adjacency"},
	{"lf06_directional_regularity", "maximum eligible uplink/downlink1/(1+CVpositive same-direction header-availability gaps), pooled only within TCP flow instances", "8 positive gaps and200ms summed within-flow gap span in a direction; no negative gaps"},
}

func definitionsSHA() string {
	raw, _ := json.Marshal(featureDefinitions)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type aggregation struct {
	OrderingAmbiguous bool               `json:"ordering_ambiguous"`
	MaskedFeatures    []string           `json:"masked_features"`
	Applicable        bool               `json:"applicable_to_primary"`
	CoverageEligible  bool               `json:"coverage_eligible"`
	CoverageReasons   []string           `json:"coverage_reasons"`
	Statistics        *stats             `json:"statistics"`
	Features          map[string]feature `json:"features"`
	Diagnostics       diagnostics        `json:"diagnostics"`
}
type flowAggregation struct {
	HeaderEvidenceAbsent                  bool                 `json:"header_evidence_absent"`
	TCPSequenceCensusComplete             bool                 `json:"tcp_sequence_census_complete"`
	PrimaryTCPSequenceCensusComplete      bool                 `json:"primary_tcp_sequence_census_complete"`
	WholeCaptureTCPSequenceCensusComplete bool                 `json:"whole_capture_tcp_sequence_census_complete"`
	PrimaryEvidenceEnds                   *time.Time           `json:"primary_evidence_ends_utc"`
	TLSHeaderParseValid                   bool                 `json:"tls_header_parse_valid"`
	PrimaryTLSHeaderParseValid            bool                 `json:"primary_tls_header_parse_valid"`
	WholeCaptureTLSHeaderParseValid       bool                 `json:"whole_capture_tls_header_parse_valid"`
	TLSHeaders                            uint64               `json:"total_tls_record_headers"`
	PrimaryTLS23Headers                   uint64               `json:"primary_tls23_headers"`
	TLS23Headers                          uint64               `json:"tls23_headers"`
	Streams                               []StreamEvidence     `json:"tls_streams"`
	IssueTimestamps                       map[string]time.Time `json:"issue_timestamps"`
	RawTCPPayloadBytes                    uint64               `json:"raw_tcp_payload_bytes_including_retransmits"`
	PrimaryScope                          bool                 `json:"primary_scope"`
	SetupState                            string               `json:"setup_state"`
	SYNACK                                bool                 `json:"syn_ack_captured"`
	RSTCaptured                           bool                 `json:"rst_captured"`
	FINCaptured                           bool                 `json:"fin_captured"`
	ID                                    string               `json:"flow_id"`
	Tuple                                 Tuple                `json:"five_tuple"`
	SYN                                   *time.Time           `json:"syn_utc"`
	First                                 *time.Time           `json:"first_tls23_header_available_utc"`
	Closed                                *time.Time           `json:"closed_utc"`
	aggregation
}
type longReport struct {
	HeaderEvidenceAbsent        bool                `json:"header_evidence_absent"`
	EvidenceUnit                string              `json:"evidence_unit"`
	GroupFirstHeaderAvailable   *time.Time          `json:"group_first_tls23_header_available_utc"`
	CoverageSHA                 string              `json:"coverage_semantics_sha256"`
	ZeroPayloadSetupOnly        bool                `json:"zero_payload_setup_only"`
	OrderingSHA                 string              `json:"ordering_semantics_sha256"`
	CollectorFlowCensored       bool                `json:"collector_flow_censored"`
	CollectorOmittedFlowRecords uint64              `json:"collector_omitted_flow_records"`
	Schema                      int                 `json:"schema"`
	Version                     string              `json:"version"`
	ParserBaselineSHA           string              `json:"parser_baseline_source_sha256"`
	DefinitionsSHA              string              `json:"feature_definitions_sha256"`
	FeatureCatalog              []featureDefinition `json:"feature_catalog"`
	Metadata                    Metadata            `json:"metadata"`
	PCAPSHA                     string              `json:"pcap_sha256"`
	Start                       time.Time           `json:"primary_start_utc"`
	End                         time.Time           `json:"primary_end_utc"`
	Group                       aggregation         `json:"group"`
	Flows                       []flowAggregation   `json:"flows"`
	Clock                       ClockDiagnostics    `json:"clock_diagnostics"`
	ParserCounters              map[string]uint64   `json:"parser_counters"`
	ParserCoverage              bool                `json:"source_observer_coverage_complete"`
	PrimaryRecords              uint64              `json:"primary_tls23_headers"`
	BeforeRecords               uint64              `json:"before_primary_tls23_headers"`
	AfterRecords                uint64              `json:"after_primary_tls23_headers"`
	WholeCaptureRecords         uint64              `json:"whole_capture_tls23_headers"`
	HistogramEntries            int                 `json:"histogram_entries_retained"`
	Limits                      map[string]int      `json:"limits"`
	Scope                       []string            `json:"scope"`
}

func unique(reasons []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range reasons {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}
func maskedLong(s *stats) []string {
	if s.OrderingAmbiguous {
		return []string{"lf05_immediate_reply_share"}
	}
	return []string{}
}

func summarize(source Report) longReport {
	c := source.long
	result := longReport{Schema: 4, HeaderEvidenceAbsent: source.HeaderEvidenceAbsent, EvidenceUnit: source.EvidenceUnit, GroupFirstHeaderAvailable: source.GroupAnchor, CoverageSHA: CoverageSemanticsSHA, ZeroPayloadSetupOnly: source.ZeroPayloadSetupOnly, Version: LongflowVersion, OrderingSHA: OrderingSemanticsSHA, CollectorFlowCensored: c.flowCountCensored, CollectorOmittedFlowRecords: c.omittedFlowRecords, ParserBaselineSHA: ParserBaselineSHA, DefinitionsSHA: definitionsSHA(), FeatureCatalog: featureDefinitions, Metadata: source.Metadata, PCAPSHA: source.PCAPSHA, Start: utc(c.start), End: utc(c.end), Flows: []flowAggregation{}, Clock: source.ClockDiagnostics, ParserCounters: source.Counters, ParserCoverage: source.CoverageComplete, PrimaryRecords: c.group.Records, BeforeRecords: c.before, AfterRecords: c.after, HistogramEntries: c.histogramEntries, Limits: map[string]int{"histogram_distinct_per_flow": MaxDistinctPerFlow, "histogram_distinct_group": MaxDistinctGroup, "histogram_entries_global": MaxHistogramEntries, "flows": MaxFlows, "pcap_bytes": GroupByteCap, "tcp_pending_global_bytes": MaxPendingGlobal, "clock_samples": 32}, Scope: []string{"Unclassified feature metadata only: no fitting/threshold/stealth or ISP claim.", "All complete TLS23 headers available inside declared primary80s; no64-header aggregate cutoff. Length is DECLARED body plus5 header bytes, not delivered ciphertext bytes; body completion not required.", "Group transition/pair/gap statistics pool within TCP flows only; never pair across entries or use nativeSID/nonce/sourceID.", "G04 directional TCP/header causal checks remain strict; cross-direction ambiguity masks LF05, with raw timestamps/file order unchanged. Header availability is not request/reply causality.", "Feature eligibility includes coverage and predefined support; invalid numeric diagnostics are not classifier inputs.", "Histograms bounded explicitly; concentration abstains on censor, other exact counters continue.", "The final combined detector and any companions must use ONE joint groupANDdirect-flow calibration; this extractor calibrates nothing.", "Full80 header statistics include encrypted handshakeTLS23; open partial bodies and verified close aborts remain explicit diagnostics, not complete TLS sessions. NativeUDP/end-to-end proofs and external capture accounting require separate joins."}}
	groupReasons := append([]string{}, source.GlobalReasons...)
	if c.flowCountCensored {
		groupReasons = append(groupReasons, "collector_flow_count_censored")
	}
	if !source.CoverageComplete {
		groupReasons = append(groupReasons, "source_observer_primary_coverage_incomplete")
	}

	for _, flow := range source.Flows {
		result.WholeCaptureRecords += flow.Records
		s := c.flows[flow.ID]
		if s == nil {
			s = &stats{Lengths: map[int]uint64{}}
		}
		applicable := flow.PrimaryTLS23Headers > 0
		reasons := append([]string{}, source.GlobalReasons...)

		if applicable {
			for reason, at := range flow.issueAt {
				if at < c.end {
					reasons = append(reasons, reason)
				}
			}
			for _, w := range flow.Windows {
				if w.Primary && w.Status != "not_applicable" && !w.Eligible {
					reasons = append(reasons, "declared_flow_or_prefix_coverage_incomplete")
				}
			}
		} else {
			reasons = append(reasons, "no_TLS23_flow_in_primary")
		}
		reasons = unique(reasons)
		coverage := applicable && len(reasons) == 0
		features, diag := scalarFeatures(s, coverage)
		result.Flows = append(result.Flows, flowAggregation{HeaderEvidenceAbsent: flow.HeaderEvidenceAbsent, TCPSequenceCensusComplete: flow.TCPSequenceCensusComplete, PrimaryTCPSequenceCensusComplete: flow.PrimaryTCPSequenceCensusComplete, WholeCaptureTCPSequenceCensusComplete: flow.WholeCaptureTCPSequenceCensusComplete, PrimaryEvidenceEnds: flow.PrimaryEvidenceEnds, TLSHeaderParseValid: flow.TLSHeaderParseValid, PrimaryTLSHeaderParseValid: flow.PrimaryTLSHeaderParseValid, WholeCaptureTLSHeaderParseValid: flow.WholeCaptureTLSHeaderParseValid, TLSHeaders: flow.TLSHeaders, PrimaryTLS23Headers: flow.PrimaryTLS23Headers, TLS23Headers: flow.Records, Streams: flow.Streams, IssueTimestamps: flow.IssueTimestamps, RawTCPPayloadBytes: flow.RawTCPPayloadBytes, PrimaryScope: flow.PrimaryScope, SetupState: flow.SetupState, SYNACK: flow.SYNACK, RSTCaptured: flow.RSTCaptured, FINCaptured: flow.FINCaptured, ID: flow.ID, Tuple: flow.Tuple, SYN: flow.SYN, First: flow.First, Closed: flow.Closed, aggregation: aggregation{OrderingAmbiguous: s.OrderingAmbiguous, MaskedFeatures: maskedLong(s), Applicable: applicable, CoverageEligible: coverage, CoverageReasons: reasons, Statistics: s, Features: features, Diagnostics: diag}})
	}
	groupReasons = unique(groupReasons)
	coverage := len(groupReasons) == 0
	features, diag := scalarFeatures(&c.group, coverage)
	result.Group = aggregation{OrderingAmbiguous: c.group.OrderingAmbiguous, MaskedFeatures: maskedLong(&c.group), Applicable: true, CoverageEligible: coverage, CoverageReasons: groupReasons, Statistics: &c.group, Features: features, Diagnostics: diag}
	return result
}
func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}
func run(args []string) error {
	fs := flag.NewFlagSet("longflow", flag.ContinueOnError)
	pcap := fs.String("pcap", "", "classic PCAP")
	meta := fs.String("meta", "", "explicit prelaunch80s VMmetadata")
	out := fs.String("out", "", "feature JSON")
	version := fs.Bool("version", false, "version")
	catalog := fs.Bool("catalog", false, "write feature catalog without reading data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version {
		fmt.Println(LongflowVersion)
		return nil
	}
	if *catalog {
		if *out == "" {
			return fmt.Errorf("-catalog requires -out")
		}
		return writeJSON(*out, map[string]any{"version": LongflowVersion, "definitions_sha256": definitionsSHA(), "features": featureDefinitions})
	}
	if *pcap == "" || *meta == "" || *out == "" {
		return fmt.Errorf("-pcap -meta -out required")
	}
	raw, err := os.ReadFile(*meta)
	if err != nil {
		return err
	}
	var m Metadata
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.MeasurementStartMicros <= 0 || m.MeasuredSeconds != 80 {
		return fmt.Errorf("longflow requires explicit VMmeasurement_start_unix_micros and measured_seconds80; no implicit anchor")
	}
	source, err := extract(*pcap, m)
	if err != nil {
		return err
	}
	report := summarize(source)
	if err = writeJSON(*out, report); err != nil {
		return err
	}
	fmt.Printf("full80s TLS23records=%d flows=%d aggregatecoverage=%v histogramentries=%d; no classifier\n", report.PrimaryRecords, len(report.Flows), report.Group.CoverageEligible, report.HistogramEntries)
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

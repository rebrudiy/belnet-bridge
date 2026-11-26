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
	{"lf01_exact26_share", "TLS23 records with full record length26 bytes / all TLS23 records inside primary80s", "16 records"},
	{"lf02_tiny_le64_share", "TLS23 records with full record length<=64 bytes / all TLS23 records inside primary80s", "16 records"},
	{"lf03_length_concentration", "1 - exact Shannon length entropy / log2(record count); censored histogram abstains", "16 records; exact uncensored length histogram"},
	{"lf04_duplex_byte_balance", "1-abs(upTLSbytes-downTLSbytes)/(upTLSbytes+downTLSbytes)", "16 records and4 in each direction"},
	{"lf05_immediate_reply_share", "within-flow uplink immediately followed by downlink within0..10ms / uplink records; no cross-flow pairing", "16 records and8 uplink; unambiguous cross-direction order including raw/projected ties; no negative adjacency"},
	{"lf06_directional_regularity", "maximum eligible uplink/downlink1/(1+CVpositive same-direction gaps), pooled only within TCP flow instances", "8 positive gaps and200ms summed within-flow gap span in a direction; no negative gaps"},
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
	ID     string     `json:"flow_id"`
	Tuple  Tuple      `json:"five_tuple"`
	SYN    *time.Time `json:"syn_utc"`
	First  *time.Time `json:"first_tls23_utc"`
	Closed *time.Time `json:"closed_utc"`
	aggregation
}
type longReport struct {
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
	PrimaryRecords              uint64              `json:"primary_tls23_records"`
	BeforeRecords               uint64              `json:"before_primary_tls23_records"`
	AfterRecords                uint64              `json:"after_primary_tls23_records"`
	WholeCaptureRecords         uint64              `json:"whole_capture_tls23_records"`
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
	result := longReport{Schema: 2, Version: LongflowVersion, OrderingSHA: OrderingSemanticsSHA, CollectorFlowCensored: c.flowCountCensored, CollectorOmittedFlowRecords: c.omittedFlowRecords, ParserBaselineSHA: ParserBaselineSHA, DefinitionsSHA: definitionsSHA(), FeatureCatalog: featureDefinitions, Metadata: source.Metadata, PCAPSHA: source.PCAPSHA, Start: utc(c.start), End: utc(c.end), Flows: []flowAggregation{}, Clock: source.ClockDiagnostics, ParserCounters: source.Counters, ParserCoverage: source.CoverageComplete, PrimaryRecords: c.group.Records, BeforeRecords: c.before, AfterRecords: c.after, HistogramEntries: c.histogramEntries, Limits: map[string]int{"histogram_distinct_per_flow": MaxDistinctPerFlow, "histogram_distinct_group": MaxDistinctGroup, "histogram_entries_global": MaxHistogramEntries, "flows": MaxFlows, "pcap_bytes": GroupByteCap, "tcp_pending_global_bytes": MaxPendingGlobal, "clock_samples": 32}, Scope: []string{"Unclassified feature metadata only: no fitting/threshold/stealth or ISP claim.", "All completed TLS23 records inside declared primary80s; no64-record aggregate cutoff. Length includes5-byte TLS header.", "Group transition/pair/gap statistics pool within TCP flows only; never pair across entries or use nativeSID/nonce/sourceID.", "V2 directional TCP/TLS causal checks remain strict; cross-direction ambiguity masks LF05, with raw timestamps/file order unchanged.", "Feature eligibility includes coverage and predefined support; invalid numeric diagnostics are not classifier inputs.", "Histograms bounded explicitly; concentration abstains on censor, other exact counters continue.", "The final combined detector and any companions must use ONE joint groupANDdirect-flow calibration; this extractor calibrates nothing.", "Full80 statistics include encrypted handshakeTLS23; nativeUDP/end-to-end proofs and external capture accounting require separate joins."}}
	groupReasons := append([]string{}, source.GlobalReasons...)
	if c.flowCountCensored {
		groupReasons = append(groupReasons, "collector_flow_count_censored")
	}
	if !source.CoverageComplete {
		groupReasons = append(groupReasons, "source_observer_primary_coverage_incomplete")
	}
	if c.before > 0 {
		groupReasons = append(groupReasons, "TLS23_before_declared_prelaunch_measurement")
	}
	for _, flow := range source.Flows {
		result.WholeCaptureRecords += flow.Records
		s := c.flows[flow.ID]
		if s == nil {
			s = &stats{Lengths: map[int]uint64{}}
		}
		applicable := s.Records > 0 || (flow.First != nil && flow.First.UnixNano() < c.end && (flow.Closed == nil || flow.Closed.UnixNano() >= c.start))
		reasons := append([]string{}, source.GlobalReasons...)
		if flow.First != nil && flow.First.UnixNano() < c.start {
			reasons = append(reasons, "TLS23_before_declared_prelaunch_measurement")
		}
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
		result.Flows = append(result.Flows, flowAggregation{ID: flow.ID, Tuple: flow.Tuple, SYN: flow.SYN, First: flow.First, Closed: flow.Closed, aggregation: aggregation{OrderingAmbiguous: s.OrderingAmbiguous, MaskedFeatures: maskedLong(s), Applicable: applicable, CoverageEligible: coverage, CoverageReasons: reasons, Statistics: s, Features: features, Diagnostics: diag}})
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

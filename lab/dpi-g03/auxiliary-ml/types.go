package main

import (
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"time"
)

const Version = "g03-auxiliary-ml-v1"
const OrderingSHA = "a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1"
const MinimumRecords = 16

var FixedConfig = traffic.TrainingConfig{Seed: 2026111907, Trees: 128, Depth: 8, FPRBudget: .05}

type Assignment struct {
	GroupID          string `json:"group_id"`
	Split            string `json:"split"`
	Class            string `json:"class"`
	Profile          string `json:"profile"`
	SourceWorkloadID string `json:"source_workload_id"`
	Scope            string `json:"scope"`
	Transport        string `json:"transport"`
	ClientStack      string `json:"client_stack"`
}
type Freeze struct {
	Schema          int                    `json:"schema"`
	Role            string                 `json:"role"`
	Stage           string                 `json:"stage"`
	Frozen          time.Time              `json:"frozen_at"`
	Viability       string                 `json:"stage_a_viability"`
	CollectorSHA    string                 `json:"collector_freeze_sha256"`
	ObserverSHA     string                 `json:"observer_sha256"`
	ObserverVersion string                 `json:"observer_version"`
	OrderingSHA     string                 `json:"ordering_semantics_sha256"`
	AuxiliarySHA    string                 `json:"auxiliary_binary_sha256"`
	FeaturesSHA     string                 `json:"feature_definitions_sha256"`
	LibrarySHA      string                 `json:"library_source_sha256"`
	ReleasePath     string                 `json:"data_release_path"`
	ReleaseSHA      string                 `json:"data_release_sha256"`
	DevelopmentSHA  string                 `json:"development_freeze_sha256,omitempty"`
	PolicySHA       string                 `json:"auxiliary_policy_sha256,omitempty"`
	MeasuredSeconds int                    `json:"measured_seconds"`
	CaptureSeconds  int                    `json:"capture_seconds"`
	PrefixGrace     int                    `json:"prefix_grace_seconds"`
	WindowOffsets   []int                  `json:"window_offsets_seconds"`
	WindowSeconds   int                    `json:"window_seconds"`
	CaptureCap      int64                  `json:"capture_cap_bytes"`
	Budget          float64                `json:"group_fpr_budget"`
	FlowBudget      float64                `json:"direct_flow_fpr_budget"`
	Config          traffic.TrainingConfig `json:"hyperparameters"`
	Groups          []Assignment           `json:"groups"`
}
type Release struct {
	Schema         int       `json:"schema"`
	Role           string    `json:"role"`
	Stage          string    `json:"stage"`
	CollectorSHA   string    `json:"collector_freeze_sha256"`
	Issued         time.Time `json:"issued_at"`
	Finished       bool      `json:"acquisition_finished"`
	ReadAuthorized bool      `json:"read_authorized"`
	FitAuthorized  bool      `json:"fit_authorized"`
}
type Metadata struct {
	Assignment
	CaptureStarted         time.Time `json:"capture_started_utc"`
	CaptureEnded           time.Time `json:"capture_ended_utc"`
	FreezeSHA              string    `json:"freeze_sha256"`
	MeasurementStartMicros int64     `json:"measurement_start_unix_micros"`
	MeasuredSeconds        int       `json:"measured_seconds"`
	PrefixGrace            int       `json:"prefix_grace_seconds"`
	WindowOffsets          []int     `json:"window_offsets_seconds"`
	CaptureCap             int64     `json:"capture_cap_bytes"`
}
type Event struct {
	RawNS     int64  `json:"raw_ns"`
	Ordinal   uint64 `json:"ordinal"`
	At        int64  `json:"at_micros"`
	Direction int    `json:"direction"`
	Bytes     int    `json:"bytes"`
}
type Window struct {
	ID                string             `json:"session_id"`
	GroupID           string             `json:"group_id"`
	Split             string             `json:"split"`
	Class             string             `json:"class"`
	Profile           string             `json:"profile"`
	FlowID            string             `json:"flow_id"`
	Kind              string             `json:"window_kind"`
	Start             time.Time          `json:"window_start_utc"`
	End               time.Time          `json:"window_end_utc"`
	Eligible          bool               `json:"eligible"`
	Primary           bool               `json:"primary"`
	Status            string             `json:"status"`
	Reasons           []string           `json:"coverage_reasons"`
	OrderingAmbiguous bool               `json:"ordering_ambiguous"`
	MaskedRules       []string           `json:"masked_rules"`
	Events            []Event            `json:"events"`
	Scores            map[string]float64 `json:"scores,omitempty"`
}
type FlowSummary struct {
	ID    string     `json:"flow_id"`
	First *time.Time `json:"first_tls23_utc"`
}
type Capture struct {
	Schema           int           `json:"schema"`
	Version          string        `json:"version"`
	OrderingSHA      string        `json:"ordering_semantics_sha256"`
	Metadata         Metadata      `json:"metadata"`
	PCAPSHA          string        `json:"pcap_sha256"`
	MeasurementStart *time.Time    `json:"measurement_start_utc"`
	MeasurementEnd   *time.Time    `json:"measurement_end_utc"`
	Anchor           *time.Time    `json:"group_first_tls23_utc"`
	Coverage         bool          `json:"coverage_complete"`
	GlobalReasons    []string      `json:"global_coverage_reasons"`
	GroupWindows     []Window      `json:"group_windows"`
	Windows          []Window      `json:"windows"`
	Flows            []FlowSummary `json:"flows"`
}
type Group struct {
	Metadata        Metadata        `json:"metadata"`
	Complete        bool            `json:"coverage_complete"`
	Reasons         []string        `json:"coverage_reasons"`
	Windows         []Window        `json:"windows"`
	Diagnostics     []Window        `json:"diagnostic_windows"`
	PrimaryTLSFlows map[string]bool `json:"primary_tls_flow_inventory"`
	SourceSHA       string          `json:"source_sha256"`
	PCAPSHA         string          `json:"pcap_sha256"`
	OrderingSHA     string          `json:"ordering_semantics_sha256"`
}
type ReportRef struct {
	GroupID        string   `json:"group_id"`
	Split          string   `json:"split"`
	Path           string   `json:"path"`
	CoverageErrors []string `json:"coverage_errors,omitempty"`
}
type Index struct {
	Schema         int         `json:"schema"`
	Stage          string      `json:"stage"`
	Reports        []ReportRef `json:"reports"`
	CoverageErrors []string    `json:"coverage_errors,omitempty"`
}
type Metrics struct {
	EligibleBenignFlows int      `json:"evidence_eligible_benign_flows"`
	EligibleFlowFPR     *float64 `json:"eligible_direct_flow_fpr"`
	Groups              int      `json:"groups"`
	Complete            int      `json:"complete_groups"`
	Incomplete          int      `json:"incomplete_groups"`
	Benign              int      `json:"benign_groups"`
	Positive            int      `json:"positive_groups"`
	FP                  int      `json:"false_positive_groups"`
	TP                  int      `json:"detected_positive_groups"`
	GroupFPR            *float64 `json:"observed_group_fpr"`
	GroupTPR            *float64 `json:"observed_group_tpr"`
	Flows               int      `json:"actual_flows"`
	BenignFlows         int      `json:"benign_flows"`
	FPFlows             int      `json:"direct_rule_hit_false_positive_flows"`
	FlowFPR             *float64 `json:"direct_flow_fpr"`
	EligibleBenign      int      `json:"evidence_eligible_benign_groups"`
	EligiblePositive    int      `json:"evidence_eligible_positive_groups"`
	EligibleFPR         *float64 `json:"eligible_group_fpr"`
	Abstain             int      `json:"abstaining_groups"`
	Windows             int      `json:"primary_windows"`
	EligibleWindows     int      `json:"ML_eligible_windows"`
	MaskedWindows       int      `json:"ambiguous_masked_windows"`
	SparseWindows       int      `json:"sparse_windows"`
}
type WindowDecision struct {
	ID        string   `json:"session_id"`
	FlowID    string   `json:"flow_id"`
	Eligible  bool     `json:"eligible"`
	Score     *float64 `json:"score"`
	Detected  bool     `json:"detected"`
	Reasons   []string `json:"abstention_reasons"`
	Ambiguous bool     `json:"ordering_ambiguous"`
}
type Decision struct {
	GroupID     string           `json:"group_id"`
	Split       string           `json:"split"`
	Class       string           `json:"class"`
	ClientStack string           `json:"client_stack"`
	Profile     string           `json:"profile"`
	Complete    bool             `json:"coverage_complete"`
	Reasons     []string         `json:"coverage_reasons"`
	Status      string           `json:"status"`
	Eligible    bool             `json:"evidence_eligible"`
	Detected    bool             `json:"detected"`
	Windows     []WindowDecision `json:"windows"`
}
type Policy struct {
	Schema                 int                    `json:"schema"`
	Role                   string                 `json:"role"`
	Version                string                 `json:"version"`
	FreezeSHA              string                 `json:"freeze_sha256"`
	FeaturesSHA            string                 `json:"feature_definitions_sha256"`
	LibrarySHA             string                 `json:"library_source_sha256"`
	OrderingSHA            string                 `json:"ordering_semantics_sha256"`
	Config                 traffic.TrainingConfig `json:"hyperparameters"`
	Threshold              float64                `json:"joint_group_flow_threshold"`
	Disabled               bool                   `json:"disabled"`
	DisabledReason         string                 `json:"disabled_reason,omitempty"`
	Model                  *traffic.Model         `json:"model,omitempty"`
	CalibrationSHA         string                 `json:"scored_calibration_sha256"`
	TrainingGroups         int                    `json:"training_groups"`
	TrainingWindows        int                    `json:"training_windows"`
	ValidationWindows      int                    `json:"benign_validation_windows"`
	Calibration            map[string]Metrics     `json:"calibration"`
	FrozenAt               time.Time              `json:"policy_frozen_at"`
	LastDevelopmentCapture time.Time              `json:"last_development_capture_ended_utc"`
	Limits                 []string               `json:"limits"`
}

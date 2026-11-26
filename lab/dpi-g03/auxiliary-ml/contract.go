package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rebrudiy/belnet-bridge/internal/traffic"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Role = "auxiliary-ml"

func sha(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func read(path string, target any) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (256<<20)+1))
	if err != nil {
		return "", err
	}
	if len(raw) > 256<<20 {
		return "", fmt.Errorf("JSON input exceeds256MiB bound")
	}
	if err = json.Unmarshal(raw, target); err != nil {
		return "", err
	}
	return sha(raw), nil
}
func write(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}
func hexSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func featureContract() any {
	return struct {
		Version       string                 `json:"version"`
		LibrarySHA    string                 `json:"library_source_sha256"`
		OrderingSHA   string                 `json:"ordering_semantics_sha256"`
		Features      []string               `json:"feature_names"`
		Config        traffic.TrainingConfig `json:"hyperparameters"`
		Minimum       int                    `json:"minimum_records"`
		WindowSeconds int                    `json:"window_seconds"`
		MaxRecords    int                    `json:"max_records"`
		Ambiguity     string                 `json:"ambiguity_policy"`
		Calibration   string                 `json:"calibration"`
	}{Version, LibrarySourceSHA, OrderingSHA, traffic.FeatureNames(), FixedConfig, MinimumRecords, 2, 64, "all ordering-ambiguous windows abstain; canonical capture-time sensor view only; no ordinal fork", "ONE separate strict score>threshold over actualgroupMAX andactualflowMAX acrossallwindows/reconnects; benigntrain+benignval each<=5%; neverORwithclassicalclaimed5%; majority-unsupported classes/windows are AUX_INCONCLUSIVE"}
}
func definitionsSHA() string { raw, _ := json.Marshal(featureContract()); return sha(raw) }
func validateFreeze(f Freeze) error {
	if f.Schema != 1 || f.Role != Role || (f.Stage != "B1" && f.Stage != "B2") || f.Viability != "proceed" || f.Frozen.IsZero() {
		return fmt.Errorf("auxiliary schema1 role/stage/proceed freeze required")
	}
	if f.OrderingSHA != OrderingSHA || f.FeaturesSHA != definitionsSHA() || f.LibrarySHA != LibrarySourceSHA || !hexSHA(f.AuxiliarySHA) || !hexSHA(f.CollectorSHA) || !hexSHA(f.ObserverSHA) || f.ObserverVersion != "g03-observer-v2" || !hexSHA(f.ReleaseSHA) || f.ReleasePath == "" {
		return fmt.Errorf("auxiliary observer/library/features/ordering/binary/release pins required")
	}
	if f.Config != FixedConfig || f.MeasuredSeconds != 80 || f.CaptureSeconds != 82 || f.PrefixGrace != 2 || f.WindowSeconds != 2 || f.CaptureCap != 256*1024*1024 || f.Budget != .05 || f.FlowBudget != .05 {
		return fmt.Errorf("predeclared auxiliary hyperparameters/80s/joint5%% contract mismatch")
	}
	if f.Stage == "B2" && (!hexSHA(f.DevelopmentSHA) || !hexSHA(f.PolicySHA)) {
		return fmt.Errorf("B2 requires exact auxiliary policy/development freezeSHA")
	}
	if len(f.WindowOffsets) == 0 || len(f.WindowOffsets) > 45 || len(f.Groups) == 0 || len(f.Groups) > 128 {
		return fmt.Errorf("bounded nonempty schedule/cohort required")
	}
	prev := -1
	for _, off := range f.WindowOffsets {
		if off < 0 || off <= prev || off > 78 {
			return fmt.Errorf("invalid frozen window schedule")
		}
		prev = off
	}
	seen := map[string]bool{}
	pairs := map[string]string{}
	for _, a := range f.Groups {
		if a.GroupID == "" || seen[a.GroupID] || a.Profile == "" || a.Scope != "primary" || a.SourceWorkloadID == "" || a.ClientStack == "" || (a.Class != "benign" && a.Class != "belnet") {
			return fmt.Errorf("invalid/diagnostic assignment")
		}
		if (f.Stage == "B1" && a.Split != "train" && a.Split != "validation") || (f.Stage == "B2" && a.Split != "test") {
			return fmt.Errorf("stage rejects test/Q/development split before index/report reads")
		}
		if a.Class == "benign" && a.Transport != "ordinary-tls" || a.Class == "belnet" && a.Transport != "reality" {
			return fmt.Errorf("primary transport/class mismatch; REALITY-otherpayload notbenign FP")
		}
		if split, ok := pairs[a.SourceWorkloadID]; ok && split != a.Split {
			return fmt.Errorf("paired source workload crosses splits")
		}
		pairs[a.SourceWorkloadID] = a.Split
		seen[a.GroupID] = true
	}
	return nil
}

// A separate explicit release must be checked BEFORE even opening the index.
// The preparatory tooling cannot authorize or infer completion of actual B data.
func releaseGate(f Freeze, freezePath string, fit bool) error {
	path := f.ReleasePath
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(freezePath), path)
	}
	var r Release
	digest, err := read(path, &r)
	if err != nil {
		return err
	}
	if digest != f.ReleaseSHA || r.Schema != 1 || r.Role != "auxiliary-data-release" || r.Stage != f.Stage || r.CollectorSHA != f.CollectorSHA || r.Issued.IsZero() || !r.Issued.After(f.Frozen) || !r.Finished || !r.ReadAuthorized || (fit && (!r.FitAuthorized || f.Stage != "B1")) {
		return fmt.Errorf("actual auxiliary data remains gated: complete/explicit read/fit release required")
	}
	return nil
}
func policyBinding(p Policy, f Freeze, freezeSHA, policySHA string) error {
	if f.Stage == "B1" {
		if p.FreezeSHA != freezeSHA {
			return fmt.Errorf("B1 auxiliary development freeze mismatch")
		}
	} else if p.FreezeSHA != f.DevelopmentSHA || policySHA != f.PolicySHA || !f.Frozen.After(p.FrozenAt) {
		return fmt.Errorf("B2 exact auxiliary policy/development pin and later collector freeze required")
	}
	if p.FrozenAt.IsZero() || p.LastDevelopmentCapture.IsZero() || !p.FrozenAt.After(p.LastDevelopmentCapture) {
		return fmt.Errorf("auxiliary final freeze must follow development captures")
	}
	return nil
}
func testChronology(groups []Group, p Policy) error {
	for _, g := range groups {
		if g.Metadata.Split == "test" {
			if g.Metadata.CaptureStarted.IsZero() && !g.Complete {
				continue
			}
			if !g.Metadata.CaptureStarted.After(p.FrozenAt) {
				return fmt.Errorf("test capture predates auxiliary final policy; cannot be heldout")
			}
		}
	}
	return nil
}
func latestCapture(groups []Group) time.Time {
	var latest time.Time
	for _, g := range groups {
		if g.Metadata.CaptureEnded.After(latest) {
			latest = g.Metadata.CaptureEnded
		}
	}
	return latest
}

func releasedCaptureClock(f Freeze, freezePath string, groups []Group) error {
	path := f.ReleasePath
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(freezePath), path)
	}
	var r Release
	digest, err := read(path, &r)
	if err != nil {
		return err
	}
	if digest != f.ReleaseSHA {
		return fmt.Errorf("release changed while loading cohort")
	}
	if r.Issued.Before(latestCapture(groups)) {
		return fmt.Errorf("release predates capture completion; gates not chronologically cleared")
	}
	return nil
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureFreeze() Freeze {
	return Freeze{Schema: 1, Role: Role, Stage: "B1", Viability: "proceed", Frozen: time.Unix(100, 0).UTC(), CollectorSHA: strings.Repeat("c", 64), ObserverSHA: strings.Repeat("d", 64), ObserverVersion: "g03-observer-v2", OrderingSHA: OrderingSHA, AuxiliarySHA: strings.Repeat("a", 64), FeaturesSHA: definitionsSHA(), LibrarySHA: LibrarySourceSHA, ReleasePath: "release.json", ReleaseSHA: strings.Repeat("f", 64), MeasuredSeconds: 80, CaptureSeconds: 82, PrefixGrace: 2, WindowOffsets: []int{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78}, WindowSeconds: 2, CaptureCap: 256 * 1024 * 1024, Budget: .05, FlowBudget: .05, Config: FixedConfig, Groups: []Assignment{assigned("g", "train", "benign")}}
}
func fixtureCapture(f Freeze) Capture {
	a := f.Groups[0]
	start := time.Unix(200, 0).UTC()
	end := start.Add(80 * time.Second)
	first := start.Add(time.Second)
	c := Capture{Schema: 4, Version: f.ObserverVersion, OrderingSHA: f.OrderingSHA, Metadata: Metadata{Assignment: a, CaptureStarted: start, CaptureEnded: start.Add(82 * time.Second), MeasurementStartMicros: start.UnixMicro(), MeasuredSeconds: 80, PrefixGrace: 2, WindowOffsets: f.WindowOffsets, CaptureCap: f.CaptureCap, FreezeSHA: f.CollectorSHA}, PCAPSHA: strings.Repeat("e", 64), MeasurementStart: &start, MeasurementEnd: &end, Anchor: &first, Coverage: true, Flows: []FlowSummary{{ID: "tcp0", First: &first}}}
	for i, offset := range f.WindowOffsets {
		at := start.Add(time.Duration(offset) * time.Second)
		w := Window{ID: string(rune('a' + i)), GroupID: a.GroupID, Split: a.Split, Class: a.Class, Profile: a.Profile, FlowID: "tcp0", Kind: "phase_fixed", Start: at, End: at.Add(2 * time.Second), Primary: true, Eligible: true, Status: "sparse", MaskedRules: []string{}}
		c.GroupWindows = append(c.GroupWindows, w)
		c.Windows = append(c.Windows, w)
	}
	w := fixtureGroup(a.GroupID, a.Split, a.Class, 100).Windows[0]
	w.Start = first
	w.End = first.Add(2 * time.Second)
	for i := range w.Events {
		w.Events[i].RawNS = first.UnixNano() + w.Events[i].At*1000
	}
	c.Windows = append(c.Windows, w)
	return c
}
func loadedFixture(t *testing.T, f Freeze, c Capture) []Group {
	t.Helper()
	d := t.TempDir()
	if err := write(filepath.Join(d, "capture.json"), c); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(d, "index.json")
	if err := write(index, Index{Schema: 4, Stage: "B1", Reports: []ReportRef{{GroupID: f.Groups[0].GroupID, Split: "train", Path: "capture.json"}}}); err != nil {
		t.Fatal(err)
	}
	groups, err := loadGroups(index, f, "projection", true)
	if err != nil {
		t.Fatal(err)
	}
	return groups
}
func TestReleaseGateBlocksBeforeEvenOpeningDataIndex(t *testing.T) {
	d := t.TempDir()
	f := fixtureFreeze()
	release := Release{Schema: 1, Role: "auxiliary-data-release", Stage: "B1", CollectorSHA: f.CollectorSHA, Issued: time.Unix(1000, 0).UTC(), Finished: true, ReadAuthorized: false, FitAuthorized: false}
	path := filepath.Join(d, "release.json")
	if err := write(path, release); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	f.ReleaseSHA = sha(raw)
	freeze := filepath.Join(d, "freeze.json")
	if err := write(freeze, f); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"fit", "-freeze", freeze, "-index", filepath.Join(d, "DO-NOT-OPEN-PRIVATE-INDEX"), "-out", filepath.Join(d, "model.json")})
	if err == nil || !strings.Contains(err.Error(), "remains gated") {
		t.Fatal("actual data index accessed before release", err)
	}
}
func TestStrictFitterRejectsQAndTestBeforeReportIO(t *testing.T) {
	f := fixtureFreeze()
	for _, split := range []string{"development", "test", "unknown"} {
		f.Groups[0].Split = split
		if validateFreeze(f) == nil {
			t.Fatal("nontrainvalassignment accepted", split)
		}
	}
	f = fixtureFreeze()
	if preflightIndex(Index{Schema: 4, Stage: "B1", Reports: []ReportRef{{GroupID: "sealed", Split: "test", Path: "DO-NOT-READ"}}}, f, true) == nil {
		t.Fatal("test reference accepted")
	}
	f.Groups[0].Transport = "reality"
	if validateFreeze(f) == nil {
		t.Fatal("REALITY-otherpayload primaryFP allowed")
	}
}
func TestHyperparametersAndFeatureLibraryCannotChange(t *testing.T) {
	f := fixtureFreeze()
	if err := validateFreeze(f); err != nil {
		t.Fatal(err)
	}
	f.Config.Depth++
	if validateFreeze(f) == nil {
		t.Fatal("hyperparameter change accepted")
	}
	f = fixtureFreeze()
	f.FeaturesSHA = strings.Repeat("a", 64)
	if validateFreeze(f) == nil {
		t.Fatal("unpinned feature vector accepted")
	}
	f = fixtureFreeze()
	f.LibrarySHA = strings.Repeat("b", 64)
	if validateFreeze(f) == nil {
		t.Fatal("library drift accepted")
	}
}
func TestReviewedRawSchemaMasksAndIdentityAreRetained(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	g := loadedFixture(t, f, c)
	if !g[0].Complete {
		t.Fatal("valid observer rejected", g[0].Reasons)
	}
	c.Windows[len(c.Windows)-1].Events[0].Ordinal = 0
	g = loadedFixture(t, f, c)
	if g[0].Complete {
		t.Fatal("zeroordinal accepted")
	}
	c = fixtureCapture(f)
	w := &c.Windows[len(c.Windows)-1]
	for i := range w.Events {
		w.Events[i].At = 0
		w.Events[i].RawNS = w.Start.UnixNano()
	}
	g = loadedFixture(t, f, c)
	if g[0].Complete {
		t.Fatal("visible ambiguity hidden")
	}
	c = fixtureCapture(f)
	c.Metadata.Scope = "diagnostic"
	g = loadedFixture(t, f, c)
	if g[0].Complete {
		t.Fatal("present contradictory metadata accepted")
	}
	c = fixtureCapture(f)
	c.OrderingSHA = "wrong"
	g = loadedFixture(t, f, c)
	if g[0].Complete {
		t.Fatal("mask semantics drift accepted")
	}
}
func TestOpaqueAmbiguityValidatesButMLAbstainsWholeVector(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	w := &c.Windows[len(c.Windows)-1]
	w.OrderingAmbiguous = true
	w.MaskedRules = []string{"r05", "r06", "r10", "r15"}
	g := loadedFixture(t, f, c)
	if !g[0].Complete {
		t.Fatal("valid outside64 ambiguity became corrupt", g[0].Reasons)
	}
	ok, reasons := evidence(g[0].Windows[len(g[0].Windows)-1])
	if ok || len(reasons) == 0 {
		t.Fatal("mixed vector imputed ambiguous features")
	}
}
func TestAuxiliaryB2CannotReusePrePolicyCaptures(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	p := Policy{FreezeSHA: strings.Repeat("a", 64), LastDevelopmentCapture: now.Add(-2 * time.Second), FrozenAt: now}
	f := fixtureFreeze()
	f.Stage = "B2"
	f.DevelopmentSHA = p.FreezeSHA
	f.PolicySHA = strings.Repeat("b", 64)
	f.Frozen = now.Add(time.Second)
	if err := policyBinding(p, f, "b2projection", f.PolicySHA); err != nil {
		t.Fatal(err)
	}
	g := fixtureGroup("sealed", "test", "belnet", 1200)
	g.Metadata.CaptureStarted = now.Add(-time.Second)
	if testChronology([]Group{g}, p) == nil {
		t.Fatal("old test capture became fresh")
	}
	g.Metadata.CaptureStarted = now.Add(time.Second)
	if err := testChronology([]Group{g}, p); err != nil {
		t.Fatal(err)
	}
}

func TestWorkingCLISyntheticGateFitAndEvaluation(t *testing.T) {
	d := t.TempDir()
	f := fixtureFreeze()
	f.Groups = nil
	index := Index{Schema: 4, Stage: "B1"}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 2; i++ {
			for _, class := range []string{"benign", "belnet"} {
				a := assigned(fmt.Sprintf("%s-%s-%d", split, class, i), split, class)
				f.Groups = append(f.Groups, a)
			}
		}
	}
	for _, a := range f.Groups {
		one := f
		one.Groups = []Assignment{a}
		c := fixtureCapture(one)
		if a.Class == "belnet" {
			for i := range c.Windows[len(c.Windows)-1].Events {
				c.Windows[len(c.Windows)-1].Events[i].Bytes = 1200
			}
		}
		name := a.GroupID + ".json"
		if err := write(filepath.Join(d, name), c); err != nil {
			t.Fatal(err)
		}
		index.Reports = append(index.Reports, ReportRef{GroupID: a.GroupID, Split: a.Split, Path: name})
	}
	release := Release{Schema: 1, Role: "auxiliary-data-release", Stage: "B1", CollectorSHA: f.CollectorSHA, Issued: time.Unix(1000, 0).UTC(), Finished: true, ReadAuthorized: true, FitAuthorized: true}
	releasePath := filepath.Join(d, "release.json")
	if err := write(releasePath, release); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(releasePath)
	f.ReleaseSHA = sha(raw)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	f.AuxiliarySHA = sha(binary)
	freeze := filepath.Join(d, "freeze.json")
	indexPath := filepath.Join(d, "index.json")
	if err = write(freeze, f); err != nil {
		t.Fatal(err)
	}
	if err = write(indexPath, index); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(d, "policy.json")
	if err = run([]string{"fit", "-freeze", freeze, "-index", indexPath, "-out", policyPath}); err != nil {
		t.Fatal("synthetic gatedCLI fit", err)
	}
	var p Policy
	if _, err = read(policyPath, &p); err != nil {
		t.Fatal(err)
	}
	if p.Model == nil || !p.FrozenAt.After(p.LastDevelopmentCapture) {
		t.Fatal("model/chronology notretained")
	}
	reportPath := filepath.Join(d, "report.json")
	if err = run([]string{"evaluate", "-freeze", freeze, "-index", indexPath, "-policy", policyPath, "-out", reportPath}); err != nil {
		t.Fatal("syntheticCLI evaluate", err)
	}
	var report struct {
		Role   string  `json:"role"`
		Status string  `json:"status"`
		All    Metrics `json:"all"`
	}
	if _, err = read(reportPath, &report); err != nil {
		t.Fatal(err)
	}
	if report.Role != Role || report.All.Groups != 8 || report.All.FlowFPR == nil || *report.All.FlowFPR > .05 || !strings.Contains(report.Status, "INCONCLUSIVE") {
		t.Fatal("coverage/auxiliary result misrepresented", report)
	}
	if run([]string{"fit", "-freeze", freeze, "-index", indexPath, "-out", policyPath}) == nil {
		t.Fatal("frozen artifact overwritten")
	}
}

func TestB2PolicyMustValidateBeforeOpeningSealedIndex(t *testing.T) {
	d := t.TempDir()
	f := fixtureFreeze()
	f.Stage = "B2"
	f.Groups[0].Split = "test"
	f.DevelopmentSHA = strings.Repeat("b", 64)
	f.PolicySHA = strings.Repeat("e", 64)
	r := Release{Schema: 1, Role: "auxiliary-data-release", Stage: "B2", CollectorSHA: f.CollectorSHA, Issued: time.Unix(1000, 0).UTC(), Finished: true, ReadAuthorized: true}
	rp := filepath.Join(d, "release.json")
	if err := write(rp, r); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(rp)
	f.ReleaseSHA = sha(raw)
	self, _ := os.Executable()
	binary, _ := os.ReadFile(self)
	f.AuxiliarySHA = sha(binary)
	fp := filepath.Join(d, "freeze.json")
	if err := write(fp, f); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"evaluate", "-freeze", fp, "-index", filepath.Join(d, "DO-NOT-OPEN-SEALED"), "-policy", filepath.Join(d, "NO-FINAL-POLICY"), "-out", filepath.Join(d, "report.json")})
	if err == nil || !strings.Contains(err.Error(), "NO-FINAL-POLICY") {
		t.Fatal("sealed index opened before valid final auxiliary policy", err)
	}
}

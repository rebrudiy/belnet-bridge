package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureCapture(a Assignment, f Freeze) Capture {
	start := time.Unix(200, 0).UTC()
	end := start.Add(80 * time.Second)
	first := start.Add(time.Second)
	c := Capture{Schema: 3, Version: "g03-observer-v1", Metadata: Metadata{Assignment: a, CaptureStarted: start, CaptureEnded: start.Add(82 * time.Second), FreezeSHA: f.CollectorSHA, CaptureCap: f.CaptureCap, MeasuredSeconds: 80, MeasurementStartMicros: start.UnixMicro(), PrefixGrace: 2, WindowOffsets: f.WindowOffsets}, Coverage: true, PCAPSHA: strings.Repeat("e", 64), Anchor: &first, MeasurementStart: &start, MeasurementEnd: &end, Flows: []FlowSummary{{ID: "initial", First: &first}}}
	for i, offset := range f.WindowOffsets {
		at := start.Add(time.Duration(offset) * time.Second)
		c.GroupWindows = append(c.GroupWindows, Window{ID: fmt.Sprintf("group%d", i), Start: at, End: at.Add(2 * time.Second), Kind: "group-coverage", Primary: true, Eligible: true, Status: "sparse"})
		c.Windows = append(c.Windows, Window{ID: fmt.Sprintf("%s/fixed%d", a.GroupID, i), GroupID: a.GroupID, Split: a.Split, Class: a.Class, Profile: a.Profile, FlowID: "initial", Kind: "phase_fixed", Start: at, End: at.Add(2 * time.Second), Primary: true, Eligible: true, Status: "sparse", Events: []Event{}})
	}
	c.Windows = append(c.Windows, Window{ID: a.GroupID + "/initial-prefix", GroupID: a.GroupID, Split: a.Split, Class: a.Class, Profile: a.Profile, FlowID: "initial", Kind: "flow-prefix", Start: first, End: first.Add(2 * time.Second), Primary: true, Eligible: true, Status: "complete", Events: []Event{{At: 0, Direction: 1, Bytes: 32}}})
	return c
}
func fixtureIndex(t *testing.T, dir string, f Freeze, captures []Capture) string {
	t.Helper()
	index := Index{Schema: 3, Stage: f.Stage}
	for i, c := range captures {
		name := fmt.Sprintf("capture%d.json", i)
		if err := write(filepath.Join(dir, name), c); err != nil {
			t.Fatal(err)
		}
		index.Reports = append(index.Reports, ReportRef{GroupID: c.Metadata.GroupID, Split: c.Metadata.Split, Path: name})
	}
	path := filepath.Join(dir, "index.json")
	if err := write(path, index); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestG03ObserverPrimaryRoundTripAndMissingCensoredAggregation(t *testing.T) {
	dir := t.TempDir()
	f := fixtureFreeze()
	a := f.Groups[0]
	c := fixtureCapture(a, f)
	index := fixtureIndex(t, dir, f, []Capture{c})
	groups, err := loadGroups(index, f, "projection-sha", true)
	if err != nil || len(groups) != 1 || !groups[0].Complete || len(groups[0].Windows) != 12 {
		t.Fatal("schema3/11offset/initialprefix failed", err, groups)
	}
	c.Windows[11].Primary = false
	index = fixtureIndex(t, dir, f, []Capture{c})
	groups, err = loadGroups(index, f, "projection-sha", true)
	if err != nil || groups[0].Complete {
		t.Fatal("initial prefix hidden from primary", err)
	}
	c = fixtureCapture(a, f)
	c.Coverage = false
	c.GlobalReasons = []string{"byte_censored"}
	index = fixtureIndex(t, dir, f, []Capture{c})
	f.Groups = append(f.Groups, assignment("missing", "validation", "benign", "fixture"))
	groups, err = loadGroups(index, f, "projection-sha", true)
	if err != nil || len(groups) != 2 || len(groupErrors(groups)) != 2 {
		t.Fatal("missing/censored groups vanished or fail-fast", err, groups)
	}
	ds := evaluate(groups, Policy{})
	for _, d := range ds {
		if d.Complete || d.Status != "incomplete_undetermined" {
			t.Fatal("coverage failure became pass", d)
		}
	}
}
func TestB1RejectsTestReferencesBeforeOpeningAndScoring(t *testing.T) {
	dir := t.TempDir()
	f := fixtureFreeze()
	path := filepath.Join(dir, "freeze.json")
	if err := write(path, f); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(dir, "index.json")
	if err := write(index, Index{Schema: 3, Stage: "B1", Reports: []ReportRef{{GroupID: "sealed", Split: "test", Path: "DO-NOT-READ.json"}}}); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"fit", "-freeze", path, "-index", index, "-engine", filepath.Join(dir, "DO-NOT-INVOKE"), "-out", filepath.Join(dir, "policy.json")})
	if err == nil || !strings.Contains(err.Error(), "before opening") {
		t.Fatal("test path/engine reached before preflight", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "policy.json.rejected.json")); err != nil {
		t.Fatal("rejection evidence missing", err)
	}
	f.Stage = "B2"
	f.Groups[0].Split = "test"
	f.DevelopmentSHA = strings.Repeat("f", 64)
	f.PolicySHA = strings.Repeat("e", 64)
	if preflightIndex(Index{Schema: 3, Stage: "B2"}, f, true) == nil {
		t.Fatal("B2 fitting allowed")
	}
}
func TestPrimaryREALITYOtherPayloadAndPairedSplitLeakRejected(t *testing.T) {
	f := fixtureFreeze()
	f.Groups[0].Transport = "reality"
	if validateFreeze(f) == nil {
		t.Fatal("REALITY-other-payload entered primary benign")
	}
	f = fixtureFreeze()
	other := assignment("other", "validation", "belnet", "fixture")
	other.SourceWorkloadID = f.Groups[0].SourceWorkloadID
	f.Groups = append(f.Groups, other)
	if validateFreeze(f) == nil {
		t.Fatal("paired source-workload crossed splits")
	}
	f = fixtureFreeze()
	f.Groups[0].Scope = "diagnostic"
	if validateFreeze(f) == nil {
		t.Fatal("diagnostic entered primary")
	}
}
func TestPolicyAndFreshB2ChronologyBindings(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	p := Policy{FreezeSHA: strings.Repeat("a", 64), LastDevelopmentCapture: now.Add(-2 * time.Second), FrozenAt: now}
	f := fixtureFreeze()
	f.Stage = "B2"
	f.Frozen = now.Add(time.Second)
	f.DevelopmentSHA = p.FreezeSHA
	f.PolicySHA = strings.Repeat("b", 64)
	if err := policyBinding(p, f, "B2projection", f.PolicySHA); err != nil {
		t.Fatal(err)
	}
	if policyBinding(p, f, "B2projection", strings.Repeat("c", 64)) == nil {
		t.Fatal("changed policy accepted")
	}
	f.Frozen = now.Add(-time.Second)
	if policyBinding(p, f, "B2projection", f.PolicySHA) == nil {
		t.Fatal("B2 frozen before final policy")
	}
	g := syntheticGroup("sealed", "test", "belnet")
	g.Metadata.CaptureStarted = now.Add(-time.Second)
	if validateTestChronology([]Group{g}, p) == nil {
		t.Fatal("old test capture accepted as fresh")
	}
	g.Metadata.CaptureStarted = now.Add(time.Second)
	if err := validateTestChronology([]Group{g}, p); err != nil {
		t.Fatal(err)
	}
	g.Metadata.CaptureStarted = time.Time{}
	g.Complete = false
	if err := validateTestChronology([]Group{g}, p); err != nil {
		t.Fatal("missing capture must remain explicit unknown", err)
	}
}
func TestClassifierEmptyDisabledAndEvidenceAbstention(t *testing.T) {
	g := syntheticGroup("ordinary", "train", "benign")
	g.Windows = []Window{{ID: "w", FlowID: "f", Eligible: true, Scores: map[string]float64{"r01": .8}}}
	p := Policy{Rules: []RulePolicy{{Rule: fixtureCatalog().Rules[0], Threshold: 2, Enabled: false}}}
	d := evaluate([]Group{g}, p)[0]
	if !d.ClassifierEmpty || !d.Abstained || d.Status != "classifier_empty_or_all_rules_disabled_abstain" || d.Detected {
		t.Fatal("disabled classifier looked like nondetection", d)
	}
	p.Rules[0].Enabled = true
	p.Rules[0].Threshold = .9
	g.Windows[0].Scores = map[string]float64{"r02": .8}
	d = evaluate([]Group{g}, p)[0]
	if !d.Abstained || d.Status != "enabled_rules_have_no_evidence_abstain" {
		t.Fatal("disabled-only evidence treated as useful", d)
	}
	g.Windows[0].Scores = map[string]float64{}
	d = evaluate([]Group{g}, p)[0]
	if !d.Abstained || d.Status != "complete_sparse_or_insufficient_rules_abstain" {
		t.Fatal(d)
	}
}
func TestGraceOutside80CreatesNoExtraObligation(t *testing.T) {
	dir := t.TempDir()
	f := fixtureFreeze()
	c := fixtureCapture(f.Groups[0], f)
	start := *c.MeasurementStart
	late := start.Add(81 * time.Second)
	c.Flows = append(c.Flows, FlowSummary{ID: "grace", First: &late})
	for i, offset := range f.WindowOffsets {
		at := start.Add(time.Duration(offset) * time.Second)
		c.Windows = append(c.Windows, Window{ID: fmt.Sprintf("grace-fixed%d", i), GroupID: c.Metadata.GroupID, Split: c.Metadata.Split, Class: c.Metadata.Class, Profile: c.Metadata.Profile, FlowID: "grace", Kind: "phase_fixed", Start: at, End: at.Add(2 * time.Second), Primary: true, Eligible: false, Status: "not_applicable"})
	}
	c.Windows = append(c.Windows, Window{ID: "grace-prefix", GroupID: c.Metadata.GroupID, Split: c.Metadata.Split, Class: c.Metadata.Class, Profile: c.Metadata.Profile, FlowID: "grace", Kind: "flow-prefix", Start: late, End: late.Add(2 * time.Second), Primary: false, Eligible: false, Status: "not_applicable"})
	groups, err := loadGroups(fixtureIndex(t, dir, f, []Capture{c}), f, "projection", true)
	if err != nil || !groups[0].Complete || len(groups[0].Windows) != 12 || len(groups[0].Diagnostics) != 12 {
		t.Fatal("grace created primary failure/denominator", err, groups)
	}
}

func TestDynamicFrozenOffsetsNotHardcodedFourOrEleven(t *testing.T) {
	dir := t.TempDir()
	f := fixtureFreeze()
	f.WindowOffsets = []int{0, 8, 78}
	c := fixtureCapture(f.Groups[0], f)
	groups, err := loadGroups(fixtureIndex(t, dir, f, []Capture{c}), f, "projection", true)
	if err != nil || !groups[0].Complete || len(groups[0].Windows) != 4 {
		t.Fatal("frozen dynamic schedule not honored", err, groups)
	}
}
func TestWorkingB1CLIFitAndEvaluateWithPinnedExistingEngine(t *testing.T) {
	dir := t.TempDir()
	engine := filepath.Join(dir, "classical")
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", engine, "./lab/dpi-v2/classical")
	command.Dir = root
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build unchanged engine: %v %s", err, raw)
	}
	catalog, err := catalog(engine, dir)
	if err != nil {
		t.Fatal(err)
	}
	engineRaw, err := os.ReadFile(engine)
	if err != nil {
		t.Fatal(err)
	}
	f := fixtureFreeze()
	f.EngineSHA = sha(engineRaw)
	f.DefinitionsSHA = catalog.SHA
	f.Groups = []Assignment{assignment("ordinary-train", "train", "benign", "fixture"), assignment("ordinary-val", "validation", "benign", "fixture"), assignment("native-train", "train", "belnet", "fixture")}
	captures := []Capture{}
	for _, a := range f.Groups {
		captures = append(captures, fixtureCapture(a, f))
	}
	index := fixtureIndex(t, dir, f, captures)
	freeze := filepath.Join(dir, "freeze.json")
	if err = write(freeze, f); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	work := filepath.Join(dir, "work")
	if err = run([]string{"fit", "-freeze", freeze, "-index", index, "-engine", engine, "-work", work, "-out", policyPath}); err != nil {
		t.Fatal("working B1 fit failed", err)
	}
	var p Policy
	if _, err = read(policyPath, &p); err != nil {
		t.Fatal(err)
	}
	if p.Schema != 3 || p.MeasuredSeconds != 80 || !p.FrozenAt.After(p.LastDevelopmentCapture) || len(p.Calibration) != 2 {
		t.Fatal("wrong working policy", p)
	}
	report := filepath.Join(dir, "report.json")
	if err = run([]string{"evaluate", "-freeze", freeze, "-index", index, "-policy", policyPath, "-engine", engine, "-work", work, "-out", report}); err != nil {
		t.Fatal("working B1 evaluation failed", err)
	}
	var r struct {
		Decisions []Decision  `json:"decisions"`
		All       Calibration `json:"all"`
	}
	if _, err = read(report, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Decisions) != 3 || r.All.Groups != 3 || r.All.Abstain != 3 {
		t.Fatal("sparse fixture was reported as bypass", r)
	}
}

func TestJointMarginCanDisableEveryIndividuallyEnabledRule(t *testing.T) {
	g := syntheticGroup("ordinary", "train", "benign")
	g.Windows = []Window{{ID: "w", FlowID: "f", Eligible: true, Scores: map[string]float64{"r01": 1}}}
	p := Policy{Rules: []RulePolicy{{Rule: fixtureCatalog().Rules[0], Threshold: .5, Enabled: true}}, Margin: .6}
	d := evaluate([]Group{g}, p)[0]
	if !d.ClassifierEmpty || !d.Abstained || d.Detected {
		t.Fatal("mathematically empty joint classifier reported as nondetection", d)
	}
	p.Margin = .5
	d = evaluate([]Group{g}, p)[0]
	if d.ClassifierEmpty || !d.Detected {
		t.Fatal("exact attainable boundary rejected", d)
	}
}

func TestExternalCaptureAccountingErrorsCannotBecomeCompletePass(t *testing.T) {
	dir := t.TempDir()
	f := fixtureFreeze()
	c := fixtureCapture(f.Groups[0], f)
	index := fixtureIndex(t, dir, f, []Capture{c})
	var ix Index
	if _, err := read(index, &ix); err != nil {
		t.Fatal(err)
	}
	ix.Reports[0].CoverageErrors = []string{"received_vs_saved_mismatch_unknown"}
	ix.CoverageErrors = []string{"VM_clock_bounds_unknown"}
	if err := write(index, ix); err != nil {
		t.Fatal(err)
	}
	groups, err := loadGroups(index, f, "projection", true)
	if err != nil || groups[0].Complete || len(groups[0].Reasons) != 2 {
		t.Fatal("external capture errors ignored", err, groups)
	}
}

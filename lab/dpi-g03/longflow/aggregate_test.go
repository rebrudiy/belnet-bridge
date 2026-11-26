package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fullMetadata() Metadata {
	m := metadata()
	m.MeasurementStartMicros = epochNS / 1000
	m.MeasuredSeconds = 80
	m.PrefixGraceSeconds = 2
	m.CaptureEnded = utc(epochNS + int64(82*time.Second))
	m.WindowOffsetsSeconds = []int64{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78}
	return m
}
func extractFixture(t *testing.T, f *fixture, m Metadata) Report {
	t.Helper()
	file := filepath.Join(t.TempDir(), "synthetic.pcap")
	if err := os.WriteFile(file, f.buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := extract(file, m)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
func TestFull80CountsEveryRecordBeyondSampledWindows(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := map[int]uint32{1: 101, -1: 401}
	for i := 0; i < 30000; i++ {
		d := 1
		if i%2 == 1 {
			d = -1
		}
		body := 95
		if i%4 == 0 {
			body = 21
		}
		r := record(body)
		f.packet(int64(i)*2_600_000+1_000_000, tcp(d, seq[d], 24, r))
		seq[d] += uint32(len(r))
	}
	// Exactly end-exclusive80s belongs to diagnostic tail, never primary count.
	f.packet(int64(80*time.Second), tcp(1, seq[1], 24, record(10)))
	source := extractFixture(t, f, fullMetadata())
	got := summarize(source)
	if !got.Group.CoverageEligible || got.PrimaryRecords != 30000 || got.AfterRecords != 1 || got.WholeCaptureRecords != 30001 {
		t.Fatal("fullhorizon records silently capped", got.PrimaryRecords, got.AfterRecords, got.Group.CoverageReasons)
	}
	if source.SelectedHighWater > 12*64 {
		t.Fatal("core selected events lost bound", source.SelectedHighWater)
	}
	if got.Group.Statistics.Exact26 != 7500 || got.Group.Statistics.Tiny64 != 7500 || len(got.Group.Statistics.Lengths) != 2 {
		t.Fatal("wrong exact statistics")
	}
	for _, id := range []string{"lf01_exact26_share", "lf02_tiny_le64_share"} {
		v := got.Group.Features[id]
		if !v.Eligible || v.Value == nil || *v.Value != .25 {
			t.Fatal(id, v)
		}
	}
	if !got.Flows[0].Features["lf06_directional_regularity"].Eligible || math.Abs(*got.Flows[0].Features["lf06_directional_regularity"].Value-1) > 1e-12 {
		t.Fatal("wholeflow regularity wrong")
	}
}
func TestNoPairingOrGapsAcrossTCPFlows(t *testing.T) {
	c := newCollector(0, int64(80*time.Second))
	c.record("entryA", 1, 26, 1_000_000)
	c.record("entryB", -1, 26, 2_000_000)
	if c.group.AdjacentPairs != 0 || c.group.UpDownPairs != 0 || c.group.ReplyLatency.Count != 0 {
		t.Fatal("invented crossentry pair")
	}
	c.record("entryA", -1, 26, 3_000_000)
	if c.group.AdjacentPairs != 1 || c.group.UpDownPairs != 1 || c.group.ReplyLatency.Mean != 2_000_000 {
		t.Fatal("withinflow pair missing")
	}
	if c.group.UpPositiveGaps.Count != 0 || c.group.DownPositiveGaps.Count != 0 {
		t.Fatal("invented crossflow gap")
	}
}
func TestHistogramCensorExplicitAndOtherCountsRemainExact(t *testing.T) {
	c := newCollector(0, int64(80*time.Second))
	for i := 0; i < MaxDistinctPerFlow+20; i++ {
		c.record("flow", 1, 100+i, int64(i+1)*1_000_000)
	}
	s := c.flows["flow"]
	features, _ := scalarFeatures(s, true)
	if !s.HistogramCensored || s.HistogramOmittedRecords != 20 || len(s.Lengths) != MaxDistinctPerFlow || s.Records != MaxDistinctPerFlow+20 {
		t.Fatal("histogram cap silent/wrong")
	}
	if features["lf03_length_concentration"].Eligible || features["lf03_length_concentration"].Value != nil || !features["lf01_exact26_share"].Eligible {
		t.Fatal("censor scope wrong", features)
	}
	for flow := 1; flow <= 20; flow++ {
		for i := 0; i < MaxDistinctPerFlow; i++ {
			c.record(fmt.Sprint(flow), 1, 100+flow*1024+i, int64(i+1)*1_000_000)
		}
	}
	if c.histogramEntries > MaxHistogramEntries || len(c.group.Lengths) > MaxDistinctGroup {
		t.Fatal("histograms unbounded")
	}
	if !c.group.HistogramCensored || c.group.Records != uint64(21*MaxDistinctPerFlow+20) {
		t.Fatal("global count stopped at cap")
	}
}
func TestCollectorFlowMemoryIndependentlyBounded(t *testing.T) {
	c := newCollector(0, int64(80*time.Second))
	for i := 0; i < MaxFlows+10; i++ {
		c.record(fmt.Sprint(i), 1, 26, int64(i))
	}
	if len(c.flows) != MaxFlows || !c.flowCountCensored || c.omittedFlowRecords != 10 || c.group.Records != MaxFlows+10 {
		t.Fatal("flow aggregation unbounded or silent")
	}
}
func TestStrictCopiedCrossFlowAndCrossDirectionClockSemantics(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(200_000, otherPort(tcp(1, 1000, 2, nil), 30001))
	f.packet(300_000, otherPort(tcp(-1, 4000, 18, nil), 30001))
	f.packet(1_000_000, tcp(1, 101, 24, record(21)))
	f.packet(984_000, otherPort(tcp(1, 1001, 24, record(21)), 30001))
	got := summarize(extractFixture(t, f, fullMetadata()))
	if !got.Group.CoverageEligible || got.Clock.CrossFlowBackwardEdges != 1 || got.Clock.MaxCrossFlowBackwardNS != 16000 || got.PrimaryRecords != 2 {
		t.Fatal("crossflow16us handling changed")
	}
	f = newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(21)))
	f.packet(984_000, tcp(-1, 401, 24, record(21)))
	got = summarize(extractFixture(t, f, fullMetadata()))
	if got.Group.CoverageEligible || got.Clock.PerFlowBackwardEdges != 1 || got.Clock.PerStreamBackwardEdges != 0 {
		t.Fatal("strict sameflow crossdirection rule was relaxed")
	}
	for _, v := range got.Flows[0].Features {
		if v.Eligible {
			t.Fatal("causal-invalid feature became eligible")
		}
	}
}
func TestSparseAndCoverageAbstentionsAreExplicit(t *testing.T) {
	s := &stats{Lengths: map[int]uint64{}}
	features, _ := scalarFeatures(s, true)
	for _, v := range features {
		if v.Eligible || len(v.Reasons) == 0 {
			t.Fatal("empty traffic looked like eligible zero", v)
		}
	}
	c := newCollector(0, int64(80*time.Second))
	for i := 0; i < 32; i++ {
		d := 1
		if i%2 == 1 {
			d = -1
		}
		c.record("f", d, 26, int64(i)*20_000_000)
	}
	features, _ = scalarFeatures(c.flows["f"], false)
	for _, v := range features {
		if v.Eligible || !contains(v.Reasons, "coverage_ineligible") {
			t.Fatal("coverage invalid ignored", v)
		}
	}
}
func TestDeterministicMetadataOnlyOutputAndExplicit80CLI(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := uint32(101)
	for i := 0; i < 30; i++ {
		r := record(21 + i%3)
		f.packet(int64(i+1)*20_000_000, tcp(1, seq, 24, r))
		seq += uint32(len(r))
	}
	dir := t.TempDir()
	pcap := filepath.Join(dir, "fixture.pcap")
	meta := filepath.Join(dir, "meta.json")
	out := filepath.Join(dir, "features.json")
	if err := os.WriteFile(pcap, f.buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(meta, fullMetadata()); err != nil {
		t.Fatal(err)
	}
	args := []string{"-pcap", pcap, "-meta", meta, "-out", out}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err = run(args); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("output not deterministic")
	}
	var report longReport
	if err = json.Unmarshal(a, &report); err != nil {
		t.Fatal(err)
	}
	if report.ParserBaselineSHA != ParserBaselineSHA || len(report.DefinitionsSHA) != 64 || len(report.Flows[0].Features) != 6 {
		t.Fatal("bad report schema")
	}
	m := fullMetadata()
	m.MeasurementStartMicros = 0
	if err = writeJSON(meta, m); err != nil {
		t.Fatal(err)
	}
	if run(args) == nil {
		t.Fatal("implicit anchor accepted by full80CLI")
	}
}

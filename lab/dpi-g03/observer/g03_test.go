package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func otherPort(packet []byte, port uint16) []byte {
	if binary.BigEndian.Uint16(packet[34:36]) == 443 {
		binary.BigEndian.PutUint16(packet[36:38], port)
	} else {
		binary.BigEndian.PutUint16(packet[34:36], port)
	}
	return packet
}
func findWindow(t *testing.T, flow *Flow, kind string) *Window {
	t.Helper()
	for _, w := range flow.Windows {
		if w.Kind == kind {
			return w
		}
	}
	t.Fatalf("missing window %s", kind)
	return nil
}
func TestCrossFlowSkewDiagnosticAndTrueMinimumAnchor(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(200_000, otherPort(tcp(1, 1000, 2, nil), 30001))
	f.packet(300_000, otherPort(tcp(-1, 4000, 18, nil), 30001))
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	f.packet(984_000, otherPort(tcp(1, 1001, 24, record(10)), 30001))
	r := f.read(t, metadata())
	if !r.CoverageComplete {
		t.Fatal("cross-flow ordering became coverage failure", r.GlobalReasons)
	}
	d := r.ClockDiagnostics
	if d.FileBackwardEdges != 1 || d.CrossFlowBackwardEdges != 1 || d.MaxCrossFlowBackwardNS != 16_000 || d.PerFlowBackwardEdges != 0 || d.PerStreamBackwardEdges != 0 {
		t.Fatalf("wrong diagnostics %+v", d)
	}
	if r.GroupAnchor.UnixNano() != epochNS+984_000 {
		t.Fatal("anchor is first processed, not minimum", r.GroupAnchor)
	}
	if got := findWindow(t, r.Flows[0], "group-fixed").Events[0].At; got != 16 {
		t.Fatal("windows not assigned to true minimum anchor", got)
	}
	if len(d.Samples) != 1 || d.Samples[0].Flow == d.Samples[0].PreviousFlow {
		t.Fatal("cross-flow sample missing", d.Samples)
	}
}
func TestSameFlowBackwardsInvalidatesFlow(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	f.packet(984_000, tcp(1, 116, 16, nil))
	r := f.read(t, metadata())
	if r.CoverageComplete || len(r.Observations) != 0 {
		t.Fatal("causal backwards flow accepted")
	}
	if r.ClockDiagnostics.PerFlowBackwardEdges != 1 || r.ClockDiagnostics.PerStreamBackwardEdges != 1 || r.ClockDiagnostics.CrossFlowBackwardEdges != 0 {
		t.Fatal(r.ClockDiagnostics)
	}
	for _, w := range r.Flows[0].Windows {
		if w.Eligible {
			t.Fatal("flow window remained eligible", w.ID)
		}
	}
}
func TestPendingSequenceArrivesBeforeGapAndUsesAvailabilityTime(t *testing.T) {
	f := newFixture(true)
	f.syn()
	a, b := record(10), record(20)
	f.packet(1_000_000, tcp(1, 101+uint32(len(a)), 24, b))
	f.packet(3_000_000, tcp(1, 101, 24, a))
	r := f.read(t, metadata())
	if !r.CoverageComplete || r.Flows[0].Records != 2 {
		t.Fatal("reassembly failed", r.GlobalReasons, r.Flows[0].Issues)
	}
	prefix := findWindow(t, r.Flows[0], "flow-prefix")
	if prefix.Start.UnixNano() != epochNS+3_000_000 || len(prefix.Events) != 2 || prefix.Events[0].At != 0 || prefix.Events[1].At != 0 {
		t.Fatal("queued record was timestamped before gap availability", prefix)
	}
}
func TestPendingRecordPreservesMaximumConstituentTimestamp(t *testing.T) {
	f := newFixture(true)
	f.syn()
	r := record(40)
	// File order contains a future-sequence segment with a later UTC timestamp.
	// The gap arrives later in file order with an earlier UTC. Remain invalid,
	// but never report record completion before the constituent at5ms.
	f.packet(5_000_000, tcp(1, 105, 24, r[4:]))
	f.packet(3_000_000, tcp(1, 101, 24, r[:4]))
	report := f.read(t, metadata())
	if report.Flows[0].First.UnixNano() != epochNS+5_000_000 {
		t.Fatal("lost pending segment timestamp", report.Flows[0].First)
	}
	if report.CoverageComplete || len(report.Observations) != 0 || report.ClockDiagnostics.PerFlowBackwardEdges != 1 {
		t.Fatal("causal anomaly was repaired instead of rejected")
	}
}
func TestPartialHeaderTimestampMaximum(t *testing.T) {
	f := newFixture(true)
	f.syn()
	r := record(10)
	f.packet(5_000_000, tcp(1, 101, 24, r[:4]))
	f.packet(3_000_000, tcp(1, 105, 24, r[4:]))
	got := f.read(t, metadata())
	if got.Flows[0].First.UnixNano() != epochNS+5_000_000 || got.CoverageComplete {
		t.Fatal("header constituent maximum or invalidation lost")
	}
}
func TestExplicitPhaseWarmupPrefixesAndDeclaredGrace(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := uint32(101)
	add := func(at int64) { r := record(10); f.packet(at, tcp(1, seq, 24, r)); seq += uint32(len(r)) }
	add(int64(time.Second))
	phase := int64(25 * time.Second)
	for _, offset := range offsets {
		add(phase + offset + 1_000_000)
	}
	f.packet(phase+int64(44*time.Second), tcp(1, 1000, 2, nil))
	f.packet(phase+int64(44*time.Second)+1000, tcp(-1, 4000, 18, nil))
	f.packet(phase+int64(44*time.Second)+2000, tcp(1, 1001, 24, record(10)))
	f.packet(phase+int64(46*time.Second), tcp(1, 2000, 2, nil))
	f.packet(phase+int64(46*time.Second)+1000, tcp(-1, 5000, 18, nil))
	f.packet(phase+int64(46*time.Second)+2000, tcp(1, 2001, 24, record(10)))
	meta := metadata()
	meta.MeasurementStartMicros = (epochNS + phase) / 1000
	meta.PrefixGraceSeconds = 2
	meta.CaptureEnded = utc(epochNS + phase + int64(47*time.Second))
	got := f.read(t, meta)
	if !got.CoverageComplete || got.Schema != 3 {
		t.Fatal("valid phase/grace rejected", got.GlobalReasons)
	}
	if got.GroupAnchor.UnixNano() != epochNS+int64(time.Second) || got.GroupWindows[3].Start.UnixNano() != epochNS+phase+int64(28*time.Second) {
		t.Fatal("phase anchor contaminated by bootstrap")
	}
	if len(got.DiagnosticObservations) != 1 || got.DiagnosticObservations[0].Kind != "bootstrap-prefix" || got.DiagnosticObservations[0].Primary {
		t.Fatal("bootstrap prefix not isolated")
	}
	for _, w := range got.Observations {
		if !w.Primary || w.Kind == "bootstrap-prefix" {
			t.Fatal("bootstrap leaked to primary observations")
		}
	}
	for _, w := range got.Flows[0].Windows {
		if w.Kind == "phase_fixed" && (len(w.Events) != 1 || w.Events[0].At != 1000) {
			t.Fatal("phase sample at wrong UTC", w)
		}
	}
	late := findWindow(t, got.Flows[1], "flow-prefix")
	if !late.Eligible || !late.Primary {
		t.Fatal("declared grace did not finish in-phase prefix", late)
	}
	grace := findWindow(t, got.Flows[2], "flow-prefix")
	if grace.Status != "not_applicable" || grace.Primary {
		t.Fatal("grace flow created primary obligation", grace)
	}
	meta.PrefixGraceSeconds = 0
	got = f.read(t, meta)
	if got.CoverageComplete || !contains(findWindow(t, got.Flows[1], "flow-prefix").Reasons, "prefix_exceeds_declared_grace") {
		t.Fatal("undeclared grace silently accepted")
	}
	meta.PrefixGraceSeconds = 2
	meta.CaptureEnded = utc(epochNS + phase + int64(45*time.Second))
	got = f.read(t, meta)
	if got.CoverageComplete {
		t.Fatal("declared grace substituted for actual capture")
	}
}
func TestExplicitPhaseRequiresEntireFortyFiveSeconds(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	meta := metadata()
	meta.MeasurementStartMicros = epochNS / 1000
	meta.CaptureEnded = utc(epochNS + int64(31*time.Second))
	got := f.read(t, meta)
	if got.CoverageComplete || !contains(got.GlobalReasons, "measurement_not_fully_captured") {
		t.Fatal("four samples substituted for full45s coverage")
	}
}
func TestInvalidPhaseMetadataAndSeekContract(t *testing.T) {
	for _, modify := range []func(*Metadata){func(m *Metadata) { m.MeasurementStartMicros = -1 }, func(m *Metadata) { m.PrefixGraceSeconds = 3 }, func(m *Metadata) { m.MeasuredSeconds = 91 }} {
		meta := metadata()
		modify(&meta)
		if _, err := newParser(meta); err == nil {
			t.Fatal("invalid phase metadata accepted")
		}
	}
	f := newFixture(true)
	f.syn()
	f.packet(1_000_000, tcp(1, 101, 24, record(10)))
	p, _ := newParser(metadata())
	if err := p.read(bytes.NewBuffer(f.buf.Bytes())); err == nil {
		t.Fatal("unbounded implicit anchor fallback")
	}
	meta := metadata()
	meta.MeasurementStartMicros = epochNS / 1000
	p, _ = newParser(meta)
	if err := p.read(bytes.NewBuffer(f.buf.Bytes())); err != nil {
		t.Fatal("explicit phase should be single-pass streaming", err)
	}
}
func TestRecordCausalReversalRemainsInvalid(t *testing.T) {
	p, _ := newParser(metadata())
	f := p.newFlow(Tuple{"10.0.0.1", 30000, "10.0.0.2", 443, "tcp"}, true, 101, epochNS)
	p.event(f, 1, 100, epochNS+2_000_000)
	p.event(f, -1, 100, epochNS+1_000_000)
	if p.report.ClockDiagnostics.RecordCausalBackwardEdges != 1 || !contains(f.Issues, "record_causal_time_reversal") {
		t.Fatal("record causal reversal ignored")
	}
}

func TestEightySecondPrelaunchHorizonKeepsInitialBootstrapPrimary(t *testing.T) {
	f := newFixture(true)
	f.syn()
	seq := uint32(101)
	// Measurement starts before all traffic; startup is primary, not hidden.
	for _, at := range []int64{1, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78} {
		r := record(10)
		f.packet(at*int64(time.Second)+1_000_000, tcp(1, seq, 24, r))
		seq += uint32(len(r))
	}
	f.packet(int64(79*time.Second), tcp(1, 1000, 2, nil))
	f.packet(int64(79*time.Second)+1000, tcp(-1, 4000, 18, nil))
	f.packet(int64(79*time.Second)+2000, tcp(1, 1001, 24, record(10)))
	meta := metadata()
	meta.MeasurementStartMicros = epochNS / 1000
	meta.MeasuredSeconds = 80
	meta.WindowOffsetsSeconds = []int64{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78}
	meta.PrefixGraceSeconds = 2
	meta.CaptureEnded = utc(epochNS + int64(82*time.Second))
	got := f.read(t, meta)
	if !got.CoverageComplete || len(got.GroupWindows) != 11 || len(got.DiagnosticObservations) != 0 {
		t.Fatal("startup exclusion or80scoverage failure", got.GlobalReasons)
	}
	initial := findWindow(t, got.Flows[0], "flow-prefix")
	if !initial.Primary || !initial.Eligible || initial.Start.UnixNano() != epochNS+int64(time.Second)+1_000_000 {
		t.Fatal("initial bootstrap removed from primary", initial)
	}
	if got.GroupWindows[10].End.UnixNano() != epochNS+int64(80*time.Second) {
		t.Fatal("late primary window lost")
	}
	late := findWindow(t, got.Flows[1], "flow-prefix")
	if !late.Primary || !late.Eligible {
		t.Fatal("79s new flow lost despite82s grace")
	}
	meta.CaptureEnded = utc(epochNS + int64(45*time.Second))
	got = f.read(t, meta)
	if got.CoverageComplete || !contains(got.GlobalReasons, "measurement_not_fully_captured") {
		t.Fatal("45s capture became80s complete")
	}
}
func TestBoundedCustomWindowOffsets(t *testing.T) {
	for _, offsets := range [][]int64{{0, 0}, {8, 0}, {-1}, {79}, {1 << 62}} {
		meta := metadata()
		meta.MeasuredSeconds = 80
		meta.WindowOffsetsSeconds = offsets
		if _, err := newParser(meta); err == nil {
			t.Fatal("invalid window offsets accepted", offsets)
		}
	}
	meta := metadata()
	meta.MeasuredSeconds = 90
	for i := int64(0); i < MaxWindows+1; i++ {
		meta.WindowOffsetsSeconds = append(meta.WindowOffsetsSeconds, i)
	}
	if _, err := newParser(meta); err == nil {
		t.Fatal("unbounded window configuration")
	}
	meta = metadata()
	meta.MeasuredSeconds = 2
	meta.WindowOffsetsSeconds = []int64{0}
	if _, err := newParser(meta); err != nil {
		t.Fatal("bounded2s explicit scope rejected", err)
	}
}

func TestGraceOnlyCausalAnomalyDoesNotCreatePrimaryObligation(t *testing.T) {
	f := newFixture(true)
	f.syn()
	f.packet(int64(time.Second), tcp(1, 101, 24, record(10)))
	f.packet(int64(81*time.Second), tcp(1, 1000, 2, nil))
	f.packet(int64(81*time.Second)+1000, tcp(-1, 4000, 18, nil))
	f.packet(int64(81*time.Second)+1_000_000, tcp(1, 1001, 24, record(10)))
	f.packet(int64(81*time.Second)+984_000, tcp(1, 1016, 16, nil))
	meta := metadata()
	meta.MeasurementStartMicros = epochNS / 1000
	meta.MeasuredSeconds = 80
	meta.WindowOffsetsSeconds = []int64{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78}
	meta.PrefixGraceSeconds = 2
	meta.CaptureEnded = utc(epochNS + int64(82*time.Second))
	got := f.read(t, meta)
	if !got.CoverageComplete {
		t.Fatal("grace-only connection created primary obligation", got.GlobalReasons)
	}
	if got.ClockDiagnostics.PerFlowBackwardEdges != 1 {
		t.Fatal("grace diagnostic lost")
	}
	prefix := findWindow(t, got.Flows[1], "flow-prefix")
	if prefix.Primary || prefix.Eligible || prefix.Status != "not_applicable" {
		t.Fatal("grace-only prefix primary", prefix)
	}
}

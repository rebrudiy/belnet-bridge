package main

import (
	"testing"
	"time"
)

func headerFixture() Capture {
	start := time.Unix(100, 0).UTC()
	first := start.Add(-time.Second)
	syn := start.Add(-2 * time.Second)
	yes := true
	raw := uint64(1000)
	all, primary, total := uint64(2), uint64(1), uint64(3)
	return Capture{EvidenceUnit: "tls23_header_declared_length", Coverage: true, Metadata: Metadata{CaptureStarted: start.Add(-3 * time.Second), CaptureEnded: start.Add(83 * time.Second), CaptureCap: 256 * 1024 * 1024}, Anchor: &first, Flows: []FlowSummary{{ID: "preexisting", Syn: &syn, SynAck: &yes, PrimaryScope: &yes, RawPayload: &raw, First: &first, HeaderCount: &all, PrimaryHeaderCount: &primary, TotalHeaderCount: &total, HeaderParseValid: &yes, SequenceCensus: &yes, PrimarySequenceCensus: &yes, PrimaryHeaderParseValid: &yes, PrimaryEvidenceEnd: func() *time.Time { e := start.Add(80 * time.Second); return &e }(), Streams: []HeaderStream{{Direction: 1, ContiguousBytes: 1000}}}}}
}
func TestPreprimaryHeaderHistoryDoesNotHideInPrimaryEvidence(t *testing.T) {
	c := headerFixture()
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) > 0 {
		t.Fatal(errs)
	}
	if c.Flows[0].First.After(time.Unix(100, 0)) || *c.Flows[0].PrimaryHeaderCount == 0 {
		t.Fatal("fixture must exercise preexisting primary evidence")
	}
}

func TestPreexistingIdleHeaderHistoryIsExplicitAbstentionWithoutNewSyn(t *testing.T) {
	c := headerFixture()
	zero := uint64(0)
	c.Flows[0].PrimaryHeaderCount = &zero
	c.HeaderEvidenceAbsent = false
	start, end := time.Unix(100, 0), time.Unix(180, 0)
	if errs := validateHeaderEvidence(c, start, end); len(errs) != 0 {
		t.Fatal(errs)
	}
	if !knownPrimaryHeaderAbsence(c, start, end) {
		t.Fatal("known sparse existing flow required new primary SYN")
	}
	g := syntheticGroup("g", "train", "benign")
	g.PrimaryFlowIDs = []string{"preexisting"}
	g.HeaderEvidenceAbsent = true
	d := evaluate([]Group{g}, Policy{})[0]
	if d.Status != "complete_no_TLS_header_evidence_abstain" || !d.Abstained || measure([]Decision{d}).Flows != 1 {
		t.Fatal("known idle history became pass or lost population", d)
	}
}

func TestPartialHeaderOnlyAfterEvidenceDeadlineDoesNotPoisonPrimary(t *testing.T) {
	c := headerFixture()
	after := time.Unix(181, 0)
	no := false
	zero := uint64(0)
	c.Flows[0].PrimaryHeaderCount = &zero
	c.Flows[0].Streams[0].HeaderPending = 3
	c.Flows[0].Streams[0].HeaderStarted = &after
	c.Flows[0].Streams[0].PartialHeaderRelevant = &no
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) > 0 {
		t.Fatal("postprimary diagnostic poisoned known header view", errs)
	}
	before := time.Unix(179, 0)
	c.Flows[0].Streams[0].HeaderStarted = &before
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("false relevance hid primary partial header")
	}
}

func TestLatePrimaryPrefixExtendsHeaderProofDeadline(t *testing.T) {
	c := headerFixture()
	first := time.Unix(179, 500000000)
	deadline := first.Add(2 * time.Second)
	c.Flows[0].First = &first
	c.Flows[0].PrimaryEvidenceEnd = &deadline
	partial := time.Unix(181, 0)
	no := false
	c.Flows[0].Streams[0].HeaderPending = 2
	c.Flows[0].Streams[0].HeaderStarted = &partial
	c.Flows[0].Streams[0].PartialHeaderRelevant = &no
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("declared prefix grace hidden by80s cutoff")
	}
	deadline = time.Unix(180, 0)
	c.Flows[0].PrimaryEvidenceEnd = &deadline
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("forged shortened proof horizon accepted")
	}
}
func TestOngoingBodyIsKnownHeaderMetadataNotCompleteTLSSession(t *testing.T) {
	c := headerFixture()
	c.Flows[0].Streams[0].BodyRemaining = 1400
	c.Flows[0].Streams[0].OpenBody = true
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) > 0 {
		t.Fatal(errs)
	}
	c.Flows[0].Streams[0].KnownBodyAbort = true
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("uncaptured close called a known abort")
	}
}
func TestClosedPartialHeaderAbsenceRequiresActualCloseAndValidCensus(t *testing.T) {
	c := headerFixture()
	zero := uint64(0)
	c.HeaderEvidenceAbsent = true
	c.Anchor = nil
	c.Flows[0].First = nil
	c.Flows[0].HeaderCount = &zero
	c.Flows[0].PrimaryHeaderCount = &zero
	c.Flows[0].Streams[0].HeaderPending = 3
	started := time.Unix(102, 0)
	relevant := true
	c.Flows[0].Streams[0].HeaderStarted = &started
	c.Flows[0].Streams[0].PartialHeaderRelevant = &relevant
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("open incomplete header became explicit absence")
	}
	s := &c.Flows[0].Streams[0]
	s.CloseCaptured = true
	closed := time.Unix(103, 0)
	s.CloseAt = &closed
	s.CloseValid = true
	s.ClosedHeaderAbstain = true
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) > 0 {
		t.Fatal("verified aborted header rejected", errs)
	}
	no := false
	c.Flows[0].SequenceCensus = &no
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("unproven census became header absence")
	}
}
func TestHeaderCounterAndAbsenceContradictionsRejected(t *testing.T) {
	for _, kind := range []string{"hidden", "count", "missing", "unit", "scope"} {
		c := headerFixture()
		switch kind {
		case "hidden":
			c.HeaderEvidenceAbsent = true
		case "count":
			v := uint64(999999)
			c.Flows[0].TotalHeaderCount = &v
		case "missing":
			c.Flows[0].HeaderCount = nil
		case "unit":
			c.EvidenceUnit = "body_complete"
		case "scope":
			no := false
			c.Flows[0].PrimaryScope = &no
		}
		if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
			t.Fatalf("accepted %s", kind)
		}
	}
}

func TestSelectedEventsCannotBeInventedOnClosedFourByteHeader(t *testing.T) {
	c := headerFixture()
	zero := uint64(0)
	four := uint64(4)
	c.Flows[0].HeaderCount = &zero
	c.Flows[0].PrimaryHeaderCount = &zero
	c.Flows[0].TotalHeaderCount = &zero
	c.Flows[0].RawPayload = &four
	c.Flows[0].First = nil
	c.Anchor = nil
	c.HeaderEvidenceAbsent = true
	c.Windows = []Window{{FlowID: "preexisting", Kind: "phase_fixed", Primary: true, Eligible: true, Start: time.Unix(100, 0), TotalRecords: 0, Events: make([]Event, 16)}}
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("selected fake records accepted withzeroheaderinventory")
	}
}

func TestFirst64HeaderSelectionRetainsExactLargeCount(t *testing.T) {
	c := headerFixture()
	n := uint64(100)
	c.Flows[0].HeaderCount = &n
	c.Flows[0].PrimaryHeaderCount = &n
	c.Flows[0].TotalHeaderCount = &n
	c.Windows = []Window{{FlowID: "preexisting", Kind: "phase_fixed", Primary: true, Eligible: true, Start: time.Unix(100, 0), TotalRecords: 100, Events: make([]Event, 64)}}
	c.GroupWindows = []Window{{Start: time.Unix(100, 0), TotalRecords: 100}}
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) > 0 {
		t.Fatal("valid countbeyond64 rejected", errs)
	}
}

func TestPartialHeaderCloseTimestampMustFollowObservedHeader(t *testing.T) {
	c := headerFixture()
	zero := uint64(0)
	c.Flows[0].First = nil
	c.Flows[0].HeaderCount = &zero
	c.Flows[0].PrimaryHeaderCount = &zero
	c.Flows[0].TotalHeaderCount = &zero
	c.HeaderEvidenceAbsent = true
	c.Anchor = nil
	started, closed := time.Unix(102, 0), time.Unix(101, 0)
	yes := true
	s := &c.Flows[0].Streams[0]
	s.HeaderPending = 4
	s.HeaderStarted = &started
	s.PartialHeaderRelevant = &yes
	s.CloseCaptured = true
	s.CloseValid = true
	s.ClosedHeaderAbstain = true
	s.CloseAt = &closed
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("closebeforeheader blessed as known abstention")
	}
	closed = time.Unix(103, 0)
	after := time.Unix(190, 0)
	no := false
	s.HeaderStarted = &after
	s.PartialHeaderRelevant = &no
	if errs := validateHeaderEvidence(c, time.Unix(100, 0), time.Unix(180, 0)); len(errs) == 0 {
		t.Fatal("headeraftercapture hidden as postprimarydiagnostic")
	}
}

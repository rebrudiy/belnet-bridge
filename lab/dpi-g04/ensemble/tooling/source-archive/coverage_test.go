package main

import (
	"testing"
	"time"
)

func TestZeroPayloadSetupIsEvidenceAbstentionNotStealth(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	scope, zero := true, uint64(0)
	syn := start.Add(time.Second)
	c := Capture{ZeroPayloadSetupOnly: true, Flows: []FlowSummary{{ID: "tcp", Syn: &syn, PrimaryScope: &scope, RawPayload: &zero}}}
	if err := validateZeroPayloadSetup(c, start, start.Add(80*time.Second)); err != nil {
		t.Fatal(err)
	}
	g := syntheticGroup("g", "train", "benign")
	g.ZeroPayloadSetupOnly = true
	g.PrimaryFlowIDs = []string{"tcp"}
	d := evaluate([]Group{g}, Policy{})[0]
	m := measure([]Decision{d})
	if d.Status != "complete_no_TLS_header_evidence_abstain" || !d.Abstained || m.Flows != 1 || m.BenignFlows != 1 {
		t.Fatalf("attempt/evidence population wrong:%+v %+v", d, m)
	}
}
func TestZeroPayloadFlagCannotHidePayloadMissingSynOrEmptyPrimary(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	scope, zero := true, uint64(0)
	syn := start.Add(time.Second)
	base := FlowSummary{ID: "tcp", Syn: &syn, PrimaryScope: &scope, RawPayload: &zero}
	for _, kind := range []string{"payload", "missing-syn", "grace", "tls"} {
		f := base
		switch kind {
		case "payload":
			n := uint64(1)
			f.RawPayload = &n
		case "missing-syn":
			f.Syn = nil
		case "grace":
			b := false
			f.PrimaryScope = &b
		case "tls":
			f.First = &syn
		}
		if err := validateZeroPayloadSetup(Capture{Flows: []FlowSummary{f}}, start, start.Add(80*time.Second)); err == nil {
			t.Fatalf("accepted%s", kind)
		}
	}
}
func TestActualAttemptDenominatorAndEvidenceDenominatorStaySeparate(t *testing.T) {
	g := syntheticGroup("g", "train", "benign")
	g.PrimaryFlowIDs = []string{"tls", "syn-only"}
	g.Windows = []Window{{ID: "tls-window", FlowID: "tls", Eligible: true, Scores: map[string]float64{"r01": .9}}}
	p := Policy{Rules: []RulePolicy{{Rule: Rule{ID: "r01"}, Threshold: .5, Enabled: true}}}
	m := measure(evaluate([]Group{g}, p))
	if m.Flows != 2 || m.BenignFlows != 2 || m.BenignEligibleFlows != 1 || m.Windows != 1 || m.FlowFPR == nil || *m.FlowFPR != .5 || m.FlowEligibleFPR == nil || *m.FlowEligibleFPR != 1 {
		t.Fatalf("actual and eligible populations conflated:%+v", m)
	}
}
func TestUnsampledPayloadWithoutHandshakeAndAckOnlyRemainUnknown(t *testing.T) {
	scope, ack, bytes := true, false, uint64(26)
	syn := time.Unix(103, 0)
	f := FlowSummary{ID: "short-3sec-clienthello", PrimaryScope: &scope, RawPayload: &bytes, Syn: &syn, SynAck: &ack}
	ids, errors := primaryInventory([]FlowSummary{f}, time.Unix(100, 0), time.Unix(180, 0))
	if len(ids) != 1 || len(errors) == 0 {
		t.Fatal("unsampled ClientHello missing handshake was accepted")
	}
	bytes = 0
	f.Syn = nil
	_, errors = primaryInventory([]FlowSummary{f}, time.Unix(100, 0), time.Unix(180, 0))
	if len(errors) == 0 {
		t.Fatal("ACK-only without captured SYN was accepted")
	}
	f.Syn = &syn
	_, errors = primaryInventory([]FlowSummary{f}, time.Unix(100, 0), time.Unix(180, 0))
	if len(errors) != 0 {
		t.Fatal("captured SYN-only attempt was invented capture loss", errors)
	}
}

func TestPrimaryScopeCannotHideCapturedAttemptOrCountGrace(t *testing.T) {
	start := time.Unix(100, 0)
	end := start.Add(80 * time.Second)
	zero := uint64(0)
	ack := false
	for _, test := range []struct {
		at    int64
		scope bool
		valid bool
	}{{103, false, false}, {181, true, false}, {103, true, true}, {181, false, true}} {
		syn := time.Unix(test.at, 0)
		scope := test.scope
		_, reasons := primaryInventory([]FlowSummary{{ID: "tcp", Syn: &syn, SynAck: &ack, RawPayload: &zero, PrimaryScope: &scope}}, start, end)
		if (len(reasons) == 0) != test.valid {
			t.Fatalf("at%d scope%v reasons%v", test.at, test.scope, reasons)
		}
	}
}
func TestZeroPrimaryMayHaveVerifiedGraceTLSButNoPrimaryTLSInAnyView(t *testing.T) {
	start := time.Unix(100, 0)
	end := start.Add(80 * time.Second)
	yes, no := true, false
	z, payload := uint64(0), uint64(20)
	s1, s2 := start.Add(3*time.Second), end.Add(time.Second)
	tls := s2.Add(time.Millisecond)
	c := Capture{Anchor: &tls, Flows: []FlowSummary{{ID: "primary", Syn: &s1, PrimaryScope: &yes, RawPayload: &z}, {ID: "grace", Syn: &s2, First: &tls, PrimaryScope: &no, RawPayload: &payload}}}
	if err := validateZeroPayloadSetup(c, start, end); err != nil {
		t.Fatal("valid diagnostic grace TLS rejected", err)
	}
	c.GroupWindows = []Window{{Start: start, End: start.Add(2 * time.Second), TotalRecords: 1}}
	if err := validateZeroPayloadSetup(c, start, end); err == nil {
		t.Fatal("group-window TLS counter hidden by flag")
	}
	c.GroupWindows = nil
	c.Windows = []Window{{Start: start, End: start.Add(2 * time.Second), Status: "not_applicable", Events: []Event{{RawNS: start.UnixNano()}}}}
	if err := validateZeroPayloadSetup(c, start, end); err == nil {
		t.Fatal("NA status hid primary TLS")
	}
}

package main

import (
	"fmt"
	"testing"
	"time"
)

func addAttempt(c *Capture, id string, offset time.Duration, primary bool) {
	start := c.Metadata.CaptureStarted
	syn := start.Add(offset)
	closed := syn.Add(time.Second)
	c.Flows = append(c.Flows, FlowSummary{ID: id, SYN: &syn, Closed: &closed, RawPayload: uint64Pointer(0), PrimaryScope: boolPointer(primary), SetupState: "setup_incomplete_no_tls_evidence"})
	for i, off := range c.Metadata.WindowOffsets {
		at := start.Add(time.Duration(off) * time.Second)
		status := "not_applicable"
		eligible := false
		if syn.Before(at.Add(2*time.Second)) && !closed.Before(at) {
			status = "sparse"
			eligible = true
		}
		c.Windows = append(c.Windows, Window{ID: fmt.Sprintf("%s-fixed-%d", id, i), GroupID: c.Metadata.GroupID, Split: c.Metadata.Split, Class: c.Metadata.Class, Profile: c.Metadata.Profile, FlowID: id, Kind: "phase_fixed", Start: at, End: at.Add(2 * time.Second), Primary: true, Eligible: eligible, Status: status, MaskedRules: []string{}})
	}
}

func TestActualPrimaryAttemptBetweenWindowsSurvivesGroupDecisionAndMetrics(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	// Entire short attempt lies between0–2 and8–10: every sampled window is NA.
	addAttempt(&c, "attempt", 3*time.Second, true)
	groups := loadedFixture(t, f, c)
	if !groups[0].Complete || len(groups[0].PrimaryFlows) != 2 || groups[0].PrimaryTLSFlows["attempt"] {
		t.Fatal("primary attempt lost or invented TLS", groups[0].Reasons, groups[0].PrimaryFlows)
	}
	for _, w := range groups[0].Windows {
		if w.FlowID == "attempt" {
			t.Fatal("fake evidence window added")
		}
	}
	ds := evaluate(groups, Policy{Model: stump(), Threshold: .5})
	if len(ds[0].PrimaryFlows) != 2 {
		t.Fatal("decision dropped primary inventory")
	}
	m := measure(ds)
	if m.Flows != 2 || m.BenignFlows != 2 || m.EligibleBenignFlows != 1 {
		t.Fatal("metrics derived denominator from supported windows", m)
	}
}

func TestPrimaryOnlySYNIsCompleteUnsupportedNotStealth(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	c.Flows = nil
	c.Windows = nil
	c.Anchor = nil
	c.ZeroPayloadSetupOnly = true
	addAttempt(&c, "attempt", 3*time.Second, true)
	groups := loadedFixture(t, f, c)
	if !groups[0].Complete || len(groups[0].PrimaryFlows) != 1 || len(groups[0].Windows) != 0 {
		t.Fatal("pure attempt lost", groups[0].Reasons)
	}
	d := evaluate(groups, Policy{Model: stump(), Threshold: .5})[0]
	m := measure([]Decision{d})
	if d.Detected || d.Eligible || d.Status != "auxiliary_INCONCLUSIVE_no_supported_windows" || m.BenignFlows != 1 || m.EligibleBenignFlows != 0 || m.Abstain != 1 {
		t.Fatal("noTLS became classifier nondetection", d, m)
	}
}

func TestGraceOnlyAttemptExcludedAndCannotWaiveNoActivity(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	addAttempt(&c, "grace", 81*time.Second, false)
	groups := loadedFixture(t, f, c)
	if !groups[0].Complete || len(groups[0].PrimaryFlows) != 1 || groups[0].PrimaryFlows["grace"] {
		t.Fatal("grace padded primary denominator", groups[0].Reasons)
	}
	c = fixtureCapture(f)
	c.Flows = nil
	c.Windows = nil
	c.Anchor = nil
	addAttempt(&c, "grace", 81*time.Second, false)
	groups = loadedFixture(t, f, c)
	if groups[0].Complete || len(groups[0].PrimaryFlows) != 0 {
		t.Fatal("no primary activity accepted")
	}
	c.ZeroPayloadSetupOnly = true
	groups = loadedFixture(t, f, c)
	if groups[0].Complete {
		t.Fatal("vacuous grace-only waiver accepted")
	}
}

func TestZeroPayloadWaiverRequiresPinsSYNNoPayloadAndNoEvidence(t *testing.T) {
	mutations := []func(*Capture){
		func(c *Capture) { c.CoverageSHA = "wrong" },
		func(c *Capture) { c.Flows[0].SYN = nil; c.Flows[0].SetupState = "unknown_missing_initial_syn" },
		func(c *Capture) {
			c.Flows[0].RawPayload = uint64Pointer(42)
			c.Flows[0].SetupState = "payload_observed"
		},
		func(c *Capture) { c.Flows[0].RawPayload = nil },
		func(c *Capture) { c.Flows[0].PrimaryScope = nil },
		func(c *Capture) { c.Flows[0].PrimaryScope = boolPointer(false) },
		func(c *Capture) { c.ZeroPayloadSetupOnly = false },
		func(c *Capture) { c.GroupWindows[0].TotalRecords = 1 },
		func(c *Capture) { c.Windows[0].TotalRecords = 1 },
	}
	for i, mutate := range mutations {
		f := fixtureFreeze()
		c := fixtureCapture(f)
		c.Flows = nil
		c.Windows = nil
		c.Anchor = nil
		c.ZeroPayloadSetupOnly = true
		addAttempt(&c, "attempt", 3*time.Second, true)
		mutate(&c)
		groups := loadedFixture(t, f, c)
		if groups[0].Complete {
			t.Fatal("invalid null-anchor waiver accepted", i)
		}
	}
	f := fixtureFreeze()
	c := fixtureCapture(f)
	c.Flows = nil
	c.Windows = nil
	c.Anchor = nil
	c.ZeroPayloadSetupOnly = true
	if loadedFixture(t, f, c)[0].Complete {
		t.Fatal("empty/vacuous null-anchor waiver accepted")
	}
}

func TestPayloadMissingHandshakeCannotHideBehindNoTLSFlag(t *testing.T) {
	for _, syn := range []bool{false, true} {
		f := fixtureFreeze()
		c := fixtureCapture(f)
		c.Flows[0].SYNACK = false
		if !syn {
			c.Flows[0].SYN = nil
			c.Flows[0].SetupState = "unknown_missing_initial_syn"
		}
		groups := loadedFixture(t, f, c)
		if groups[0].Complete {
			t.Fatal("payload without handshake accepted")
		}
	}
}

func TestJointThresholdUsesEveryActualFlowIncludingUnsupported(t *testing.T) {
	groups := []Group{}
	for _, split := range []string{"train", "validation"} {
		for i := 0; i < 40; i++ {
			g := fixtureGroup(fmt.Sprintf("%s-%d", split, i), split, "benign", 100)
			if i == 0 {
				g.Windows = nil
				g.PrimaryFlows = map[string]bool{}
				for j := 0; j < 20; j++ {
					w := fixtureGroup("spike", split, "benign", 1200).Windows[0]
					w.FlowID = fmt.Sprintf("tls-%d", j)
					g.Windows = append(g.Windows, w)
					g.PrimaryFlows[w.FlowID] = true
				}
			}
			// These are declared actual flow IDs, not fake zero-evidence windows.
			for j := 0; j < 20; j++ {
				g.PrimaryFlows[fmt.Sprintf("unsupported-%d", j)] = true
			}
			groups = append(groups, g)
		}
	}
	threshold, err := jointThreshold(groups, stump())
	if err != nil || threshold != .1 {
		t.Fatal("unsupported actual flows omitted from cutoff denominator", threshold, err)
	}
	m := measure(evaluate(groups, Policy{Model: stump(), Threshold: threshold}))
	if m.BenignFlows != 1718 || m.FPFlows != 40 || m.FlowFPR == nil || *m.FlowFPR > .05 || m.GroupFPR == nil || *m.GroupFPR > .05 || m.EligibleFlowFPR == nil || *m.EligibleFlowFPR < .3 {
		t.Fatal("actual and supported FPR not separated", m)
	}
}

func TestWrongV3CoverageOrSchemaRejected(t *testing.T) {
	f := fixtureFreeze()
	for _, mutate := range []func(*Capture){func(c *Capture) { c.Schema = 4 }, func(c *Capture) { c.Version = "g03-observer-v2" }, func(c *Capture) { c.CoverageSHA = "" }} {
		c := fixtureCapture(f)
		mutate(&c)
		if loadedFixture(t, f, c)[0].Complete {
			t.Fatal("old schema or coverage silently accepted")
		}
	}
	f.CoverageSHA = ""
	if validateFreeze(f) == nil {
		t.Fatal("unpinned projection accepted")
	}
}

func TestShortClientHelloBetweenWindowsStillUnknownDespiteObserverCoverageBoolean(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	addAttempt(&c, "hello-only", 3*time.Second, true)
	c.Flows[1].RawPayload = uint64Pointer(26)
	c.Flows[1].SetupState = "payload_observed"
	// This matches the frozen V3 synthetic PCAP reproduction: no TLS23 prefix,
	// every sampled flow window NA, separate valid TLS flow supplies the anchor.
	groups := loadedFixture(t, f, c)
	if groups[0].Complete {
		t.Fatal("observer coverage boolean hid unsampled missing handshake")
	}
	found := false
	for _, r := range groups[0].Reasons {
		if r == "primary_payload_with_missing_handshake" {
			found = true
		}
	}
	if !found {
		t.Fatal("failure was not independently proven from physical payload inventory", groups[0].Reasons)
	}
}

func TestNoTLSHandshakeAndMajorityUnsupportedFlowsRemainVisible(t *testing.T) {
	f := fixtureFreeze()
	c := fixtureCapture(f)
	c.Flows = nil
	c.Windows = nil
	c.Anchor = nil
	c.ZeroPayloadSetupOnly = true
	addAttempt(&c, "attempt", 3*time.Second, true)
	c.Flows[0].SYNACK = true
	c.Flows[0].SetupState = "handshake_observed_no_tls_evidence"
	groups := loadedFixture(t, f, c)
	if !groups[0].Complete || len(groups[0].PrimaryFlows) != 1 {
		t.Fatal("captured empty handshake not preserved", groups[0].Reasons)
	}
	base := fixtureGroups()
	for i := range base {
		for j := 0; j < 4; j++ {
			base[i].PrimaryFlows[fmt.Sprintf("no-evidence-%d", j)] = true
		}
	}
	m := measure(evaluate(base, Policy{Model: stump(), Threshold: .5}))
	if m.EligibleFlows != 16 || m.Flows != 80 || auxiliaryStatus(m, Policy{Model: stump()}) != "AUXILIARY_INCONCLUSIVE_support_or_disabled" {
		t.Fatal("majority unsupported physical flows called adequate support", m)
	}
}

func uint64Pointer(v uint64) *uint64 { return &v }
func boolPointer(v bool) *bool       { return &v }

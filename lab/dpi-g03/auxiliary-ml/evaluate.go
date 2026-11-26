package main

func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	v := float64(n) / float64(d)
	return &v
}
func evaluate(groups []Group, p Policy) []Decision {
	out := []Decision{}
	for _, g := range groups {
		d := Decision{GroupID: g.Metadata.GroupID, Split: g.Metadata.Split, Class: g.Metadata.Class, ClientStack: g.Metadata.ClientStack, Profile: g.Metadata.Profile, Complete: g.Complete, Reasons: g.Reasons, Windows: []WindowDecision{}}
		for _, w := range g.Windows {
			ok, reasons := evidence(w)
			v := WindowDecision{ID: w.ID, FlowID: w.FlowID, Eligible: ok, Reasons: reasons, Ambiguous: w.OrderingAmbiguous}
			if ok {
				d.Eligible = true
				if p.Model != nil {
					score := p.Model.Score(observation(g, w))
					v.Score = &score
					v.Detected = !p.Disabled && score > p.Threshold
					d.Detected = d.Detected || v.Detected
				}
			}
			d.Windows = append(d.Windows, v)
		}
		switch {
		case !d.Complete && d.Detected:
			d.Status = "incomplete_positive_observed"
		case !d.Complete:
			d.Status = "incomplete_UNKNOWN"
		case p.Disabled || p.Model == nil:
			d.Status = "auxiliary_INCONCLUSIVE_disabled"
		case !d.Eligible:
			d.Status = "auxiliary_INCONCLUSIVE_no_supported_windows"
		case d.Detected:
			d.Status = "detected_by_auxiliary"
		default:
			d.Status = "not_detected_by_this_auxiliary_model"
		}
		out = append(out, d)
	}
	return out
}
func measure(ds []Decision) Metrics {
	m := Metrics{Groups: len(ds)}
	eligibleBenignFlows := map[string]bool{}
	allFlows, benignFlows, hitFlows := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range ds {
		if d.Complete {
			m.Complete++
		} else {
			m.Incomplete++
		}
		if d.Complete && (d.Status == "auxiliary_INCONCLUSIVE_disabled" || !d.Eligible) {
			m.Abstain++
		}
		if d.Class == "benign" {
			m.Benign++
			if d.Detected {
				m.FP++
			}
			if d.Eligible {
				m.EligibleBenign++
			}
		} else {
			m.Positive++
			if d.Detected {
				m.TP++
			}
			if d.Eligible {
				m.EligiblePositive++
			}
		}
		for _, w := range d.Windows {
			m.Windows++
			if w.Eligible {
				m.EligibleWindows++
			}
			if w.Ambiguous {
				m.MaskedWindows++
			}
			for _, r := range w.Reasons {
				if r == "need16_canonical_records" {
					m.SparseWindows++
				}
			}
			key := d.GroupID + "/" + w.FlowID
			allFlows[key] = true
			if d.Class == "benign" {
				benignFlows[key] = true
				if w.Eligible {
					eligibleBenignFlows[key] = true
				}
				if w.Detected {
					hitFlows[key] = true
				}
			}
		}
	}
	m.Flows = len(allFlows)
	m.BenignFlows = len(benignFlows)
	m.FPFlows = len(hitFlows)
	m.EligibleBenignFlows = len(eligibleBenignFlows)
	m.EligibleFlowFPR = ratio(m.FPFlows, m.EligibleBenignFlows)
	m.GroupFPR = ratio(m.FP, m.Benign)
	m.GroupTPR = ratio(m.TP, m.Positive)
	m.FlowFPR = ratio(m.FPFlows, m.BenignFlows)
	m.EligibleFPR = ratio(m.FP, m.EligibleBenign)
	return m
}
func metricsBy(ds []Decision, key func(Decision) string) map[string]Metrics {
	rows := map[string][]Decision{}
	for _, d := range ds {
		k := key(d)
		rows[k] = append(rows[k], d)
	}
	out := map[string]Metrics{}
	for k, v := range rows {
		out[k] = measure(v)
	}
	return out
}

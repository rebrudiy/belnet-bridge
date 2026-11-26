package main

import (
	"math"
	"sort"
	"time"
)

const (
	MaxDistinctPerFlow  = 1024
	MaxDistinctGroup    = 4096
	MaxHistogramEntries = 16384
	MinimumRecords      = 16
)

type moments struct {
	Count uint64  `json:"count"`
	Mean  float64 `json:"mean_ns"`
	M2    float64 `json:"m2_ns_squared"`
	Min   int64   `json:"min_ns"`
	Max   int64   `json:"max_ns"`
	Sum   float64 `json:"sum_ns"`
}

func (m *moments) add(value int64) {
	if m.Count == 0 || value < m.Min {
		m.Min = value
	}
	if value > m.Max {
		m.Max = value
	}
	m.Count++
	delta := float64(value) - m.Mean
	m.Mean += delta / float64(m.Count)
	m.M2 += delta * (float64(value) - m.Mean)
	m.Sum += float64(value)
}
func (m moments) cv() *float64 {
	if m.Count == 0 || m.Mean <= 0 {
		return nil
	}
	v := math.Sqrt(math.Max(0, m.M2/float64(m.Count))) / m.Mean
	return &v
}

type stats struct {
	Records                 uint64         `json:"records"`
	UpRecords               uint64         `json:"up_records"`
	DownRecords             uint64         `json:"down_records"`
	TLSBytes                uint64         `json:"tls_record_bytes"`
	UpBytes                 uint64         `json:"up_tls_record_bytes"`
	DownBytes               uint64         `json:"down_tls_record_bytes"`
	Exact26                 uint64         `json:"exact26_records"`
	Tiny64                  uint64         `json:"tiny_le64_records"`
	FirstNS                 *int64         `json:"first_record_completion_unix_ns"`
	LastNS                  *int64         `json:"last_record_completion_unix_ns"`
	Lengths                 map[int]uint64 `json:"exact_length_counts"`
	HistogramCensored       bool           `json:"histogram_censored"`
	HistogramOmittedRecords uint64         `json:"histogram_omitted_records"`
	AdjacentPairs           uint64         `json:"within_flow_adjacent_pairs"`
	DirectionChanges        uint64         `json:"within_flow_direction_changes"`
	UpDownPairs             uint64         `json:"within_flow_up_down_adjacent_pairs"`
	ImmediatePairs          uint64         `json:"within_flow_up_down_le10ms_pairs"`
	NegativeAdjacent        uint64         `json:"within_flow_negative_adjacent_gaps"`
	UpPositiveGaps          moments        `json:"within_flow_up_positive_gaps"`
	DownPositiveGaps        moments        `json:"within_flow_down_positive_gaps"`
	UpZeroGaps              uint64         `json:"up_zero_gaps"`
	DownZeroGaps            uint64         `json:"down_zero_gaps"`
	UpNegativeGaps          uint64         `json:"up_negative_gaps"`
	DownNegativeGaps        uint64         `json:"down_negative_gaps"`
	ReplyLatency            moments        `json:"within_flow_up_down_latency"`
	lastAt                  int64
	lastDirection           int
	haveLast                bool
	lastUp, lastDown        int64
	haveUp, haveDown        bool
}
type collector struct {
	start, end         int64
	group              stats
	flows              map[string]*stats
	histogramEntries   int
	before, after      uint64
	flowCountCensored  bool
	omittedFlowRecords uint64
}

func newCollector(start, end int64) *collector {
	return &collector{start: start, end: end, group: stats{Lengths: map[int]uint64{}}, flows: map[string]*stats{}}
}
func (c *collector) base(s *stats, direction, size int, at int64, maxDistinct int) {
	s.Records++
	s.TLSBytes += uint64(size)
	if direction == 1 {
		s.UpRecords++
		s.UpBytes += uint64(size)
	} else {
		s.DownRecords++
		s.DownBytes += uint64(size)
	}
	if size == 26 {
		s.Exact26++
	}
	if size <= 64 {
		s.Tiny64++
	}
	if s.FirstNS == nil || at < *s.FirstNS {
		v := at
		s.FirstNS = &v
	}
	if s.LastNS == nil || at > *s.LastNS {
		v := at
		s.LastNS = &v
	}
	if n, ok := s.Lengths[size]; ok {
		s.Lengths[size] = n + 1
	} else if len(s.Lengths) < maxDistinct && c.histogramEntries < MaxHistogramEntries {
		s.Lengths[size] = 1
		c.histogramEntries++
	} else {
		s.HistogramCensored = true
		s.HistogramOmittedRecords++
	}
}
func addGap(s *stats, direction int, gap int64) {
	if direction == 1 {
		if gap > 0 {
			s.UpPositiveGaps.add(gap)
		} else if gap == 0 {
			s.UpZeroGaps++
		} else {
			s.UpNegativeGaps++
		}
	}
	if direction == -1 {
		if gap > 0 {
			s.DownPositiveGaps.add(gap)
		} else if gap == 0 {
			s.DownZeroGaps++
		} else {
			s.DownNegativeGaps++
		}
	}
}
func (c *collector) record(id string, direction, size int, at int64) {
	if at < c.start {
		c.before++
		return
	}
	if at >= c.end {
		c.after++
		return
	}
	f := c.flows[id]
	if f == nil && len(c.flows) >= MaxFlows {
		c.flowCountCensored = true
		c.omittedFlowRecords++
		c.base(&c.group, direction, size, at, MaxDistinctGroup)
		return
	}
	if f == nil {
		f = &stats{Lengths: map[int]uint64{}}
		c.flows[id] = f
	}
	c.base(f, direction, size, at, MaxDistinctPerFlow)
	c.base(&c.group, direction, size, at, MaxDistinctGroup)
	if f.haveLast {
		f.AdjacentPairs++
		c.group.AdjacentPairs++
		if f.lastDirection != direction {
			f.DirectionChanges++
			c.group.DirectionChanges++
		}
		gap := at - f.lastAt
		if gap < 0 {
			f.NegativeAdjacent++
			c.group.NegativeAdjacent++
		}
		if f.lastDirection == 1 && direction == -1 && gap >= 0 {
			f.UpDownPairs++
			c.group.UpDownPairs++
			f.ReplyLatency.add(gap)
			c.group.ReplyLatency.add(gap)
			if gap <= int64(10*time.Millisecond) {
				f.ImmediatePairs++
				c.group.ImmediatePairs++
			}
		}
	}
	if direction == 1 {
		if f.haveUp {
			gap := at - f.lastUp
			addGap(f, 1, gap)
			addGap(&c.group, 1, gap)
		}
		f.haveUp = true
		f.lastUp = at
	}
	if direction == -1 {
		if f.haveDown {
			gap := at - f.lastDown
			addGap(f, -1, gap)
			addGap(&c.group, -1, gap)
		}
		f.haveDown = true
		f.lastDown = at
	}
	f.haveLast = true
	f.lastAt = at
	f.lastDirection = direction
}

type feature struct {
	Value    *float64 `json:"value"`
	Eligible bool     `json:"eligible"`
	Support  uint64   `json:"support"`
	Reasons  []string `json:"reasons"`
}
type diagnostics struct {
	EntropyBits          *float64 `json:"exact_length_entropy_bits"`
	ModalShare           *float64 `json:"exact_length_modal_share"`
	DirectionAlternation *float64 `json:"within_flow_direction_alternation"`
	UpGapCV              *float64 `json:"pooled_within_flow_up_gap_cv"`
	DownGapCV            *float64 `json:"pooled_within_flow_down_gap_cv"`
}

func value(v float64) *float64 { return &v }
func fraction(n, d uint64) *float64 {
	if d == 0 {
		return nil
	}
	return value(float64(n) / float64(d))
}
func newFeature(v *float64, support uint64, coverage bool, reasons ...string) feature {
	reasons = append([]string{}, reasons...)
	if !coverage {
		reasons = append(reasons, "coverage_ineligible")
	}
	return feature{Value: v, Support: support, Eligible: v != nil && len(reasons) == 0, Reasons: reasons}
}
func entropy(s *stats) (*float64, *float64) {
	if s.Records == 0 || s.HistogramCensored {
		return nil, nil
	}
	keys := make([]int, 0, len(s.Lengths))
	for k := range s.Lengths {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	h := 0.0
	modal := uint64(0)
	for _, k := range keys {
		n := s.Lengths[k]
		p := float64(n) / float64(s.Records)
		h -= p * math.Log2(p)
		modal = max(modal, n)
	}
	return value(h), fraction(modal, s.Records)
}
func scalarFeatures(s *stats, coverage bool) (map[string]feature, diagnostics) {
	out := map[string]feature{}
	minReasons := []string{}
	if s.Records < MinimumRecords {
		minReasons = append(minReasons, "need_at_least16_records")
	}
	out["lf01_exact26_share"] = newFeature(fraction(s.Exact26, s.Records), s.Records, coverage, minReasons...)
	out["lf02_tiny_le64_share"] = newFeature(fraction(s.Tiny64, s.Records), s.Records, coverage, minReasons...)
	h, modal := entropy(s)
	lengthReasons := append([]string{}, minReasons...)
	if s.HistogramCensored {
		lengthReasons = append(lengthReasons, "exact_length_histogram_censored")
	}
	var concentration *float64
	if h != nil && s.Records > 1 {
		concentration = value(math.Max(0, math.Min(1, 1-*h/math.Log2(float64(s.Records)))))
	}
	out["lf03_length_concentration"] = newFeature(concentration, s.Records, coverage, lengthReasons...)
	var balance *float64
	if s.TLSBytes > 0 {
		balance = value(1 - math.Abs(float64(s.UpBytes)-float64(s.DownBytes))/float64(s.TLSBytes))
	}
	balanceReasons := append([]string{}, minReasons...)
	if s.UpRecords < 4 || s.DownRecords < 4 {
		balanceReasons = append(balanceReasons, "need_at_least4_records_each_direction")
	}
	out["lf04_duplex_byte_balance"] = newFeature(balance, s.Records, coverage, balanceReasons...)
	replyReasons := append([]string{}, minReasons...)
	if s.UpRecords < 8 {
		replyReasons = append(replyReasons, "need_at_least8_uplink_records")
	}
	if s.NegativeAdjacent > 0 {
		replyReasons = append(replyReasons, "negative_within_flow_adjacency")
	}
	out["lf05_immediate_reply_share"] = newFeature(fraction(s.ImmediatePairs, s.UpRecords), s.UpRecords, coverage, replyReasons...)
	upCV, downCV := s.UpPositiveGaps.cv(), s.DownPositiveGaps.cv()
	var regularity *float64
	for _, g := range []moments{s.UpPositiveGaps, s.DownPositiveGaps} {
		if cv := g.cv(); cv != nil && g.Count >= 8 && g.Sum >= float64(200*time.Millisecond) {
			r := 1 / (1 + *cv)
			if regularity == nil || r > *regularity {
				regularity = value(r)
			}
		}
	}
	timingReasons := []string{}
	if regularity == nil {
		timingReasons = append(timingReasons, "need8_positive_same_direction_gaps_and200ms_pooled_span")
	}
	if s.UpNegativeGaps+s.DownNegativeGaps > 0 {
		timingReasons = append(timingReasons, "negative_within_stream_gaps")
	}
	out["lf06_directional_regularity"] = newFeature(regularity, s.UpPositiveGaps.Count+s.DownPositiveGaps.Count, coverage, timingReasons...)
	return out, diagnostics{EntropyBits: h, ModalShare: modal, DirectionAlternation: fraction(s.DirectionChanges, s.AdjacentPairs), UpGapCV: upCV, DownGapCV: downCV}
}

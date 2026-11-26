package traffic

import (
	"fmt"
	"math"
	"sort"
)

const prefixRecords = 24

// FeatureNames describes the fixed, versioned vector produced by Features.
func FeatureNames() []string {
	names := []string{"record_count", "out_count", "in_count", "out_bytes", "in_bytes", "duration_ms", "out_byte_fraction", "direction_change_fraction", "max_direction_run", "distinct_length_fraction", "gap_mean_ms", "gap_std_ms", "gap_max_ms", "zero_gap_fraction", "small_record_fraction", "large_record_fraction", "out_length_mean", "in_length_mean", "out_length_std", "in_length_std", "out_length_p25", "out_length_p50", "out_length_p75", "out_length_p90", "in_length_p25", "in_length_p50", "in_length_p75", "in_length_p90", "burst_count", "max_burst_bytes", "mean_burst_bytes", "out_count_fraction"}
	for i := 0; i < prefixRecords; i++ {
		names = append(names, fmt.Sprintf("signed_length_%02d", i))
	}
	for i := 0; i < prefixRecords; i++ {
		names = append(names, fmt.Sprintf("log_gap_%02d", i))
	}
	return names
}

// Features uses ciphertext length, direction and relative timing only. Session,
// group, label, split and profile fields cannot affect its output.
func Features(observation Observation) []float64 {
	events := observedEvents(observation.Events)
	f := make([]float64, 32+2*prefixRecords)
	if len(events) == 0 {
		return f
	}
	var outbound, inbound, gaps []float64
	lengths := map[int]bool{}
	var outBytes, inBytes, changes, maxRun, run, zero, small, large int
	var burstCount, burstBytes, maxBurst, totalBurst int
	for i, e := range events {
		lengths[e.Bytes] = true
		if e.Direction > 0 {
			outbound = append(outbound, float64(e.Bytes))
			outBytes += e.Bytes
		} else {
			inbound = append(inbound, float64(e.Bytes))
			inBytes += e.Bytes
		}
		gap := 0.0
		if i > 0 {
			gap = float64(e.AtMicros-events[i-1].AtMicros) / 1000
			gaps = append(gaps, gap)
			if gap == 0 {
				zero++
			}
			if e.Direction != events[i-1].Direction {
				changes++
				run = 0
			}
		}
		run++
		maxRun = max(maxRun, run)
		if i == 0 || e.Direction != events[i-1].Direction || gap >= 25 {
			if i > 0 {
				totalBurst += burstBytes
				maxBurst = max(maxBurst, burstBytes)
			}
			burstCount++
			burstBytes = 0
		}
		burstBytes += e.Bytes
		if e.Bytes <= 256 {
			small++
		}
		if e.Bytes >= 1400 {
			large++
		}
		if i < prefixRecords {
			f[32+i] = float64(e.Direction * e.Bytes)
			f[32+prefixRecords+i] = math.Log1p(math.Max(0, gap))
		}
	}
	totalBurst += burstBytes
	maxBurst = max(maxBurst, burstBytes)
	n := float64(len(events))
	totalBytes := float64(outBytes + inBytes)
	f[0] = n
	f[1] = float64(len(outbound))
	f[2] = float64(len(inbound))
	f[3] = float64(outBytes)
	f[4] = float64(inBytes)
	f[5] = float64(events[len(events)-1].AtMicros-events[0].AtMicros) / 1000
	if totalBytes > 0 {
		f[6] = float64(outBytes) / totalBytes
	}
	if len(events) > 1 {
		f[7] = float64(changes) / (n - 1)
		f[13] = float64(zero) / (n - 1)
	}
	f[8] = float64(maxRun)
	f[9] = float64(len(lengths)) / n
	f[10], f[11] = meanStd(gaps)
	for _, gap := range gaps {
		f[12] = math.Max(f[12], gap)
	}
	f[14] = float64(small) / n
	f[15] = float64(large) / n
	f[16], f[18] = meanStd(outbound)
	f[17], f[19] = meanStd(inbound)
	sort.Float64s(outbound)
	sort.Float64s(inbound)
	for i, q := range []float64{.25, .5, .75, .9} {
		f[20+i] = quantile(outbound, q)
		f[24+i] = quantile(inbound, q)
	}
	f[28] = float64(burstCount)
	f[29] = float64(maxBurst)
	f[30] = float64(totalBurst) / float64(burstCount)
	f[31] = float64(len(outbound)) / n
	return f
}

func meanStd(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range values {
		sum += x
	}
	mean := sum / float64(len(values))
	var variance float64
	for _, x := range values {
		variance += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(variance / float64(len(values)))
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	p := float64(len(sorted)-1) * q
	low := int(p)
	high := min(low+1, len(sorted)-1)
	return sorted[low] + (sorted[high]-sorted[low])*(p-float64(low))
}

// Command diagnostic inspects a frozen model on training and validation data only.
// Feature substitutions are sensitivity probes, not realizable traffic policies.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rebrudiy/belnet-bridge/internal/traffic"
)

type row struct {
	O     traffic.Observation
	X     []float64
	Score float64
}
type distribution struct {
	N      int     `json:"n"`
	Min    float64 `json:"min"`
	P25    float64 `json:"p25"`
	Median float64 `json:"median"`
	P75    float64 `json:"p75"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
}
type cohort struct {
	N       int          `json:"n"`
	Flagged int          `json:"flagged"`
	Score   distribution `json:"score"`
}
type exchange struct {
	Group     string       `json:"group"`
	Features  []string     `json:"features"`
	Source    string       `json:"source"`
	Donor     string       `json:"donor"`
	Repeats   int          `json:"repeats"`
	FlagRate  distribution `json:"flag_rate_over_repeats"`
	MeanScore distribution `json:"mean_score_over_repeats"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string, out any) []byte {
	b, e := os.ReadFile(path)
	must(e)
	must(json.Unmarshal(b, out))
	return b
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func stats(a []float64) distribution {
	if len(a) == 0 {
		return distribution{}
	}
	b := append([]float64(nil), a...)
	sort.Float64s(b)
	mean := 0.
	for _, x := range b {
		mean += x
	}
	q := func(v float64) float64 {
		pos := v * float64(len(b)-1)
		lo := int(pos)
		hi := min(lo+1, len(b)-1)
		return b[lo] + (b[hi]-b[lo])*(pos-float64(lo))
	}
	return distribution{len(b), b[0], q(.25), q(.5), q(.75), b[len(b)-1], mean / float64(len(b))}
}
func score(m *traffic.Model, x []float64) float64 {
	value := 0.
	for _, tree := range m.Trees {
		i := 0
		for !tree.Nodes[i].Leaf {
			n := tree.Nodes[i]
			if x[n.Feature] <= n.Threshold {
				i = n.Left
			} else {
				i = n.Right
			}
		}
		value += tree.Nodes[i].Probability
	}
	return value / float64(len(m.Trees))
}
func summarize(m *traffic.Model, rows []row) cohort {
	a := []float64{}
	n := 0
	for _, r := range rows {
		a = append(a, r.Score)
		if r.Score > m.Threshold {
			n++
		}
	}
	return cohort{len(rows), n, stats(a)}
}
func seq(a, b int) []int {
	x := []int{}
	for i := a; i < b; i++ {
		x = append(x, i)
	}
	return x
}
func cat(parts ...[]int) []int {
	x := []int{}
	for _, p := range parts {
		x = append(x, p...)
	}
	return x
}
func exchangeFeatures(m *traffic.Model, src, dst []row, group string, indices []int, source, donor string) exchange {
	names := traffic.FeatureNames()
	selected := []string{}
	for _, i := range indices {
		selected = append(selected, names[i])
	}
	out := exchange{Group: group, Features: selected, Source: source, Donor: donor, Repeats: 64}
	rates := []float64{}
	scores := []float64{}
	rng := rand.New(rand.NewSource(20261119091))
	for rep := 0; rep < 64; rep++ {
		flags := 0
		sum := 0.
		for _, r := range src {
			d := dst[rng.Intn(len(dst))]
			x := append([]float64(nil), r.X...)
			for _, i := range indices {
				x[i] = d.X[i]
			}
			s := score(m, x)
			sum += s
			if s > m.Threshold {
				flags++
			}
		}
		rates = append(rates, float64(flags)/float64(len(src)))
		scores = append(scores, sum/float64(len(src)))
	}
	out.FlagRate = stats(rates)
	out.MeanScore = stats(scores)
	return out
}
func dropPrefix(m *traffic.Model, rs []row, k int) cohort {
	modified := []row{}
	for _, r := range rs {
		if len(r.O.Events) <= k {
			continue
		}
		o := r.O
		o.Events = append([]traffic.Event(nil), o.Events[k:]...)
		t := o.Events[0].AtMicros
		for i := range o.Events {
			o.Events[i].AtMicros -= t
		}
		modified = append(modified, row{o, traffic.Features(o), m.Score(o)})
	}
	return summarize(m, modified)
}

type permutationResult struct {
	Group               string       `json:"group"`
	Cohort              string       `json:"cohort"`
	Repeats             int          `json:"repeats"`
	FlaggedPositiveRate distribution `json:"positive_flag_rate"`
	FalsePositiveRate   distribution `json:"benign_flag_rate"`
	BalancedAccuracy    distribution `json:"balanced_accuracy_training_only"`
}

func permutation(m *traffic.Model, rows []row, group, cohort string, indices []int) permutationResult {
	out := permutationResult{Group: group, Cohort: cohort, Repeats: 64}
	rng := rand.New(rand.NewSource(20261119092))
	tpRates, fpRates, ba := []float64{}, []float64{}, []float64{}
	for rep := 0; rep < 64; rep++ {
		order := rng.Perm(len(rows))
		tp, fp, p, n := 0, 0, 0, 0
		for i, r := range rows {
			x := append([]float64(nil), r.X...)
			for _, f := range indices {
				x[f] = rows[order[i]].X[f]
			}
			flag := score(m, x) > m.Threshold
			if r.O.Class == traffic.ClassBelNet {
				p++
				if flag {
					tp++
				}
			} else {
				n++
				if flag {
					fp++
				}
			}
		}
		if p > 0 {
			tpRates = append(tpRates, float64(tp)/float64(p))
		}
		if n > 0 {
			fpRates = append(fpRates, float64(fp)/float64(n))
		}
		if p > 0 && n > 0 {
			ba = append(ba, .5*(float64(tp)/float64(p)+1-float64(fp)/float64(n)))
		}
	}
	out.FlaggedPositiveRate = stats(tpRates)
	out.FalsePositiveRate = stats(fpRates)
	out.BalancedAccuracy = stats(ba)
	return out
}

func main() {
	base := "lab/evolution/results/full-15-queuefix-20261119"
	out := "out/dpi-next/diagnostic"
	must(os.MkdirAll(out, 0755))
	modelData, e := os.ReadFile(filepath.Join(base, "final-attacker.json"))
	must(e)
	m, e := traffic.Load(bytes.NewReader(modelData))
	must(e)
	var train, validation []traffic.Observation
	tr := read(filepath.Join(base, "final-training.json"), &train)
	va := read(filepath.Join(base, "benign-validation.json"), &validation)
	positive, negative, calibration := []row{}, []row{}, []row{}
	profiles := map[string][]row{}
	maxDelta := 0.
	for _, o := range train {
		if o.Split != traffic.SplitTrain {
			panic("nontraining data")
		}
		x := traffic.Features(o)
		s := m.Score(o)
		maxDelta = math.Max(maxDelta, math.Abs(s-score(m, x)))
		r := row{o, x, s}
		if o.Class == traffic.ClassBelNet {
			positive = append(positive, r)
			profiles[o.Profile] = append(profiles[o.Profile], r)
		} else {
			negative = append(negative, r)
		}
	}
	for _, o := range validation {
		if o.Split != traffic.SplitValidation || o.Class != traffic.ClassBenign {
			panic("invalid benign calibration")
		}
		x := traffic.Features(o)
		s := m.Score(o)
		maxDelta = math.Max(maxDelta, math.Abs(s-score(m, x)))
		calibration = append(calibration, row{o, x, s})
	}
	if maxDelta != 0 {
		panic("feature scorer differs")
	}
	groups := map[string][]int{"timing": cat([]int{5, 10, 11, 12, 13}, seq(56, 80)), "signed_prefix_lengths_mixed_direction": seq(32, 56), "length_distribution": cat([]int{3, 4, 6, 9}, seq(14, 28)), "directions_and_counts": {0, 1, 2, 7, 8, 31}, "bursts_mixed": {28, 29, 30}}
	groups["all_lengths_mixed"] = cat(groups["length_distribution"], groups["signed_prefix_lengths_mixed_direction"])
	groups["timing_and_bursts_mixed"] = cat(groups["timing"], groups["bursts_mixed"])
	groups["all_features_control"] = seq(0, 80)
	groups["timing_and_direction_counts"] = cat(groups["timing"], groups["directions_and_counts"])
	groups["timing_and_all_lengths_mixed"] = cat(groups["timing"], groups["all_lengths_mixed"])
	groups["all_except_timing"] = cat(groups["all_lengths_mixed"], groups["directions_and_counts"], groups["bursts_mixed"])
	ordered := []string{}
	for name := range groups {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	exchanges := []exchange{}
	for _, name := range ordered {
		exchanges = append(exchanges, exchangeFeatures(m, positive, negative, name, groups[name], "belnet_training", "benign_training"))
		exchanges = append(exchanges, exchangeFeatures(m, negative, positive, name, groups[name], "benign_training", "belnet_training"))
	}
	frozen := profiles["w15-c02"]
	for _, name := range ordered {
		exchanges = append(exchanges, exchangeFeatures(m, frozen, negative, name, groups[name], "frozen_profile_training", "benign_training"))
	}
	permRows := append(append([]row(nil), positive...), negative...)
	permutations := []permutationResult{}
	for _, name := range ordered {
		permutations = append(permutations, permutation(m, permRows, name, "combined_training", groups[name]))
		permutations = append(permutations, permutation(m, calibration, name, "benign_validation", groups[name]))
	}
	names := traffic.FeatureNames()
	splitCounts := make([]int, len(names))
	rootCounts := make([]int, len(names))
	for _, t := range m.Trees {
		for i, n := range t.Nodes {
			if !n.Leaf {
				splitCounts[n.Feature]++
				if i == 0 {
					rootCounts[n.Feature]++
				}
			}
		}
	}
	type featureSummary struct {
		Name       string       `json:"name"`
		SplitCount int          `json:"split_count_not_causal_importance"`
		RootCount  int          `json:"root_count_not_causal_importance"`
		Positive   distribution `json:"belnet_training"`
		Frozen     distribution `json:"frozen_profile_training"`
		Benign     distribution `json:"benign_training"`
		Validation distribution `json:"benign_validation"`
	}
	fs := []featureSummary{}
	for i, name := range names {
		get := func(rs []row) distribution {
			a := []float64{}
			for _, r := range rs {
				a = append(a, r.X[i])
			}
			return stats(a)
		}
		fs = append(fs, featureSummary{name, splitCounts[i], rootCounts[i], get(positive), get(frozen), get(negative), get(calibration)})
	}
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].RootCount != fs[j].RootCount {
			return fs[i].RootCount > fs[j].RootCount
		}
		if fs[i].SplitCount != fs[j].SplitCount {
			return fs[i].SplitCount > fs[j].SplitCount
		}
		return fs[i].Name < fs[j].Name
	})
	drops := map[string]map[string]cohort{}
	for _, k := range []int{0, 1, 2, 4, 6, 8, 12} {
		drops[fmt.Sprint(k)] = map[string]cohort{"belnet_training": dropPrefix(m, positive, k), "frozen_profile_training": dropPrefix(m, frozen, k), "benign_training": dropPrefix(m, negative, k), "benign_validation": dropPrefix(m, calibration, k)}
	}
	perProfile := map[string]cohort{}
	for k, rs := range profiles {
		perProfile[k] = summarize(m, rs)
	}
	report := map[string]any{"model_sha256": hash(modelData), "training_sha256": hash(tr), "validation_sha256": hash(va), "threshold": m.Threshold, "feature_scorer_max_difference_from_Model_Score": maxDelta, "cohorts": map[string]cohort{"belnet_training": summarize(m, positive), "benign_training": summarize(m, negative), "benign_validation": summarize(m, calibration), "frozen_profile_training": summarize(m, frozen)}, "per_profile": perProfile, "feature_distributions_and_split_counts": fs, "feature_group_substitutions": exchanges, "paired_group_permutations": permutations, "discard_initial_encrypted_records": drops, "limitations": []string{"Training positives and benign training are in-sample, not independent performance estimates.", "No final or cross-test traffic was opened or used.", "Replacing feature groups creates potentially inconsistent impossible feature vectors; this is model sensitivity, not a valid traffic attack or causal proof.", "Signed prefix sizes combine length and direction; bursts combine timing, direction and bytes.", "Removing initial encrypted records does not identify TLS-handshake boundaries and changes the trained observation distribution.", "No model fitting, threshold change, live packet acquisition or production source modification occurred."}}
	b, e := json.MarshalIndent(report, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(out, "diagnostic.json"), append(b, '\n'), 0644))
	fmt.Println("cohorts", summarize(m, positive), summarize(m, negative), summarize(m, calibration), "frozen", summarize(m, frozen))
	for _, r := range exchanges {
		if strings.Contains(r.Source, "frozen") || r.Source == "belnet_training" {
			fmt.Printf("%s %s flag=%.4f score=%.4f\n", r.Source, r.Group, r.FlagRate.Mean, r.MeanScore.Mean)
		}
	}
}

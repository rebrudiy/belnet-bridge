package traffic

import "math"

type Interval struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// Confidence bounds describe the sampled sessions, not production base rates.
// Sessions sharing a GroupID are not independent; callers must also report
// group counts and must not treat these nominal binomial intervals as coverage
// guarantees under correlated traffic.
type Metrics struct {
	TruePositive           int      `json:"true_positive"`
	FalsePositive          int      `json:"false_positive"`
	TrueNegative           int      `json:"true_negative"`
	FalseNegative          int      `json:"false_negative"`
	Positive               int      `json:"positive"`
	Negative               int      `json:"negative"`
	Groups                 int      `json:"groups"`
	TPR                    float64  `json:"tpr"`
	FPR                    float64  `json:"fpr"`
	TPRWilson95            Interval `json:"tpr_wilson95"`
	FPRWilson95            Interval `json:"fpr_wilson95"`
	ZeroFPROneSided95Upper float64  `json:"zero_fpr_one_sided95_upper,omitempty"`
}

func Evaluate(model *Model, observations []Observation) Metrics {
	var result Metrics
	groups := map[string]bool{}
	for _, o := range observations {
		groups[o.group()] = true
		blocked := model.Block(o)
		if o.Class == ClassBelNet {
			result.Positive++
			if blocked {
				result.TruePositive++
			} else {
				result.FalseNegative++
			}
		} else if o.Class == ClassBenign {
			result.Negative++
			if blocked {
				result.FalsePositive++
			} else {
				result.TrueNegative++
			}
		}
	}
	result.Groups = len(groups)
	if result.Positive > 0 {
		result.TPR = float64(result.TruePositive) / float64(result.Positive)
		result.TPRWilson95 = wilson(result.TruePositive, result.Positive)
	}
	if result.Negative > 0 {
		result.FPR = float64(result.FalsePositive) / float64(result.Negative)
		result.FPRWilson95 = wilson(result.FalsePositive, result.Negative)
		if result.FalsePositive == 0 {
			result.ZeroFPROneSided95Upper = 1 - math.Pow(.05, 1/float64(result.Negative))
		}
	}
	return result
}

func wilson(success, total int) Interval {
	if total == 0 {
		return Interval{}
	}
	n := float64(total)
	p := float64(success) / n
	z := 1.959963984540054
	denominator := 1 + z*z/n
	center := (p + z*z/(2*n)) / denominator
	half := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n)) / denominator
	return Interval{math.Max(0, center-half), math.Min(1, center+half)}
}

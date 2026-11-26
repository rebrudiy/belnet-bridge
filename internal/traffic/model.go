package traffic

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"sort"
)

type TrainingConfig struct {
	Seed      int64   `json:"seed"`
	Trees     int     `json:"trees"`
	Depth     int     `json:"depth"`
	FPRBudget float64 `json:"fpr_budget"`
}

type Model struct {
	SchemaVersion    int            `json:"schema_version"`
	FeatureNames     []string       `json:"feature_names"`
	Config           TrainingConfig `json:"config"`
	Threshold        float64        `json:"threshold"`
	Trees            []Tree         `json:"trees"`
	TrainingBelNet   int            `json:"training_belnet"`
	TrainingBenign   int            `json:"training_benign"`
	TrainingGroups   int            `json:"training_groups"`
	BenignValidation Metrics        `json:"benign_validation"`
}

type Tree struct {
	Nodes []Node `json:"nodes"`
}
type Node struct {
	Leaf        bool    `json:"leaf"`
	Probability float64 `json:"probability"`
	Feature     int     `json:"feature"`
	Threshold   float64 `json:"threshold"`
	Left        int     `json:"left"`
	Right       int     `json:"right"`
}

type sample struct {
	x        []float64
	positive bool
}

// Fit trains a balanced-bootstrap CART forest and calibrates its strict score
// threshold only against held-out benign validation. Test data is rejected.
// Fit does not promise a non-zero TPR: an empirical FPR budget may require an
// allow-all classifier, and callers must retain that outcome in their report.
func Fit(config TrainingConfig, train, benignValidation []Observation) (*Model, error) {
	if config.Trees < 1 || config.Trees > 256 || config.Depth < 1 || config.Depth > 12 || math.IsNaN(config.FPRBudget) || config.FPRBudget < 0 || config.FPRBudget >= 1 {
		return nil, fmt.Errorf("require trees 1..256, depth 1..12, FPR budget in [0,1)")
	}
	if len(benignValidation) == 0 {
		return nil, fmt.Errorf("benign validation is required for threshold calibration")
	}
	groups := map[string]bool{}
	sessions := map[string]bool{}
	var positive, negative []sample
	for _, o := range train {
		if err := o.validate(); err != nil {
			return nil, err
		}
		if o.Split != SplitTrain {
			return nil, fmt.Errorf("training observation %q has split %q", o.SessionID, o.Split)
		}
		if sessions[o.SessionID] {
			return nil, fmt.Errorf("duplicate training session %q", o.SessionID)
		}
		sessions[o.SessionID] = true
		groups[o.group()] = true
		s := sample{Features(o), o.Class == ClassBelNet}
		if s.positive {
			positive = append(positive, s)
		} else {
			negative = append(negative, s)
		}
	}
	if len(positive) < 2 || len(negative) < 2 {
		return nil, fmt.Errorf("training requires at least two sessions from each class")
	}
	for _, o := range benignValidation {
		if err := o.validate(); err != nil {
			return nil, err
		}
		if o.Split != SplitValidation || o.Class != ClassBenign {
			return nil, fmt.Errorf("calibration accepts benign validation observations only")
		}
		if groups[o.group()] || sessions[o.SessionID] {
			return nil, fmt.Errorf("training/validation group or session overlap: %q", o.SessionID)
		}
		sessions[o.SessionID] = true
	}
	m := &Model{SchemaVersion: SchemaVersion, FeatureNames: FeatureNames(), Config: config, TrainingBelNet: len(positive), TrainingBenign: len(negative), TrainingGroups: len(groups)}
	rng := rand.New(rand.NewSource(config.Seed))
	perClass := min(max(len(positive), len(negative)), 1024)
	for i := 0; i < config.Trees; i++ {
		bootstrap := make([]sample, 0, 2*perClass)
		for j := 0; j < perClass; j++ {
			bootstrap = append(bootstrap, positive[rng.Intn(len(positive))], negative[rng.Intn(len(negative))])
		}
		tree := Tree{}
		tree.build(bootstrap, config.Depth, rng)
		m.Trees = append(m.Trees, tree)
	}
	scores := make([]float64, len(benignValidation))
	for i, o := range benignValidation {
		scores[i] = m.Score(o)
	}
	sort.Float64s(scores)
	allowed := int(math.Floor(config.FPRBudget*float64(len(scores)) + 1e-12))
	m.Threshold = scores[len(scores)-allowed-1]
	m.BenignValidation = Evaluate(m, benignValidation)
	if m.BenignValidation.FalsePositive > allowed {
		return nil, fmt.Errorf("calibration exceeded empirical false-positive budget")
	}
	return m, nil
}

func (t *Tree) build(rows []sample, depth int, rng *rand.Rand) int {
	index := len(t.Nodes)
	t.Nodes = append(t.Nodes, Node{})
	pos := 0
	for _, row := range rows {
		if row.positive {
			pos++
		}
	}
	node := Node{Leaf: true, Probability: float64(pos+1) / float64(len(rows)+2)}
	if depth == 0 || len(rows) < 4 || pos == 0 || pos == len(rows) {
		t.Nodes[index] = node
		return index
	}
	features := rng.Perm(len(rows[0].x))
	features = features[:max(1, int(math.Sqrt(float64(len(features)))))]
	bestFeature := -1
	bestThreshold := 0.0
	bestCost := impurity(pos, len(rows)) * float64(len(rows))
	for _, feature := range features {
		ordered := append([]sample(nil), rows...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].x[feature] < ordered[j].x[feature] })
		leftPositive := 0
		for i := 0; i < len(ordered)-1; i++ {
			if ordered[i].positive {
				leftPositive++
			}
			left := i + 1
			right := len(ordered) - left
			if left < 2 || right < 2 || ordered[i].x[feature] == ordered[i+1].x[feature] {
				continue
			}
			cost := float64(left)*impurity(leftPositive, left) + float64(right)*impurity(pos-leftPositive, right)
			if cost+1e-12 < bestCost {
				bestCost = cost
				bestFeature = feature
				bestThreshold = ordered[i].x[feature] + (ordered[i+1].x[feature]-ordered[i].x[feature])/2
			}
		}
	}
	if bestFeature < 0 {
		t.Nodes[index] = node
		return index
	}
	var left, right []sample
	for _, row := range rows {
		if row.x[bestFeature] <= bestThreshold {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}
	node.Leaf = false
	node.Feature = bestFeature
	node.Threshold = bestThreshold
	node.Left = t.build(left, depth-1, rng)
	node.Right = t.build(right, depth-1, rng)
	t.Nodes[index] = node
	return index
}

func impurity(positive, total int) float64 {
	p := float64(positive) / float64(total)
	return 2 * p * (1 - p)
}

func (m *Model) Score(observation Observation) float64 {
	if m == nil || len(m.Trees) == 0 {
		return 0
	}
	x := Features(observation)
	score := 0.0
	for _, tree := range m.Trees {
		i := 0
		for !tree.Nodes[i].Leaf {
			node := tree.Nodes[i]
			if x[node.Feature] <= node.Threshold {
				i = node.Left
			} else {
				i = node.Right
			}
		}
		score += tree.Nodes[i].Probability
	}
	return score / float64(len(m.Trees))
}

// Block uses a strict threshold; equal-score benign ties are allowed.
func (m *Model) Block(observation Observation) bool { return m.Score(observation) > m.Threshold }

func (m *Model) Save(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(m)
}

func Load(reader io.Reader) (*Model, error) {
	var m Model
	decoder := json.NewDecoder(io.LimitReader(reader, 32<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after traffic model")
	}
	if m.SchemaVersion != SchemaVersion || len(m.FeatureNames) != len(FeatureNames()) || len(m.Trees) == 0 || len(m.Trees) > 256 || math.IsNaN(m.Threshold) || math.IsInf(m.Threshold, 0) {
		return nil, fmt.Errorf("invalid traffic model schema or threshold")
	}
	for i, name := range FeatureNames() {
		if m.FeatureNames[i] != name {
			return nil, fmt.Errorf("unsupported feature schema")
		}
	}
	for _, tree := range m.Trees {
		if len(tree.Nodes) == 0 || len(tree.Nodes) > 8191 {
			return nil, fmt.Errorf("invalid tree size")
		}
		seen := map[int]bool{}
		var visit func(int, int) error
		visit = func(index, depth int) error {
			if index < 0 || index >= len(tree.Nodes) || depth > 12 || seen[index] {
				return fmt.Errorf("invalid cyclic/shared/deep tree")
			}
			seen[index] = true
			node := tree.Nodes[index]
			if math.IsNaN(node.Probability) || math.IsInf(node.Probability, 0) || node.Probability < 0 || node.Probability > 1 {
				return fmt.Errorf("invalid tree probability")
			}
			if node.Leaf {
				return nil
			}
			if node.Feature < 0 || node.Feature >= len(m.FeatureNames) || math.IsNaN(node.Threshold) || math.IsInf(node.Threshold, 0) {
				return fmt.Errorf("invalid split")
			}
			if err := visit(node.Left, depth+1); err != nil {
				return err
			}
			return visit(node.Right, depth+1)
		}
		if err := visit(0, 0); err != nil {
			return nil, err
		}
		if len(seen) != len(tree.Nodes) {
			return nil, fmt.Errorf("unreachable tree nodes")
		}
	}
	return &m, nil
}

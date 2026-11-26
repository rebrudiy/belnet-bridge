package traffic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func example(class, split string, index int) Observation {
	length := 100 + index%7
	if class == ClassBelNet {
		length = 1200 + index%11
	}
	e := []Event{{0, 1, length}, {10000, -1, length + 10}, {20000, 1, length}}
	id := fmt.Sprintf("%s-%s-%d", class, split, index)
	return Observation{SessionID: id, GroupID: id, Split: split, Class: class, Profile: "test", Events: e}
}

func trainingData() ([]Observation, []Observation) {
	var train, val []Observation
	for i := 0; i < 40; i++ {
		train = append(train, example(ClassBelNet, SplitTrain, i), example(ClassBenign, SplitTrain, i))
	}
	for i := 0; i < 40; i++ {
		val = append(val, example(ClassBenign, SplitValidation, i))
	}
	return train, val
}

func TestForestLearnsAndCalibratesOnSeparateSessions(t *testing.T) {
	train, val := trainingData()
	config := TrainingConfig{Seed: 23, Trees: 24, Depth: 4, FPRBudget: .05}
	m, err := Fit(config, train, val)
	if err != nil {
		t.Fatal(err)
	}
	var test []Observation
	for i := 100; i < 140; i++ {
		test = append(test, example(ClassBelNet, SplitTest, i), example(ClassBenign, SplitTest, i))
	}
	metrics := Evaluate(m, test)
	if metrics.TPR < .95 || metrics.FPR > .05 {
		t.Fatalf("separable examples not learned: %+v", metrics)
	}
	if m.BenignValidation.FPR > .05 {
		t.Fatalf("threshold exceeded budget: %+v", m.BenignValidation)
	}
	if metrics.ZeroFPROneSided95Upper <= 0 || metrics.ZeroFPROneSided95Upper >= .1 {
		t.Fatal("missing finite-sample zero-FPR bound")
	}
	var encoded bytes.Buffer
	if err := m.Save(&encoded); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range test {
		if loaded.Score(o) != m.Score(o) {
			t.Fatal("score changed on model reload")
		}
	}
	m2, err := Fit(config, train, val)
	if err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	_ = m2.Save(&second)
	if !bytes.Equal(encoded.Bytes(), second.Bytes()) {
		t.Fatal("seeded training is not reproducible")
	}
}

func TestMetadataCannotLeakIntoFeaturesOrScore(t *testing.T) {
	train, val := trainingData()
	m, err := Fit(TrainingConfig{Seed: 1, Trees: 8, Depth: 3, FPRBudget: .05}, train, val)
	if err != nil {
		t.Fatal(err)
	}
	one := example(ClassBelNet, SplitTest, 100)
	two := one
	two.SessionID = "unrelated"
	two.GroupID = "different"
	two.Split = "validation"
	two.Class = ClassBenign
	two.Profile = "different wrapper"
	if !reflect.DeepEqual(Features(one), Features(two)) || m.Score(one) != m.Score(two) {
		t.Fatal("identity/label/profile metadata entered classifier")
	}
	if len(Features(one)) != len(FeatureNames()) {
		t.Fatal("feature schema mismatch")
	}
	one.Events = append(one.Events, Event{Window.Microseconds(), -1, 60000})
	if !reflect.DeepEqual(Features(one), Features(two)) {
		t.Fatal("future observation entered fixed-prefix features")
	}
}

func TestFitRejectsHoldoutLeakageAndInvalidTraining(t *testing.T) {
	config := TrainingConfig{Seed: 1, Trees: 8, Depth: 3, FPRBudget: .05}
	for _, mutate := range []func([]Observation, []Observation){
		func(train, val []Observation) { train[0].Split = SplitTest },
		func(train, val []Observation) { val[0].GroupID = train[0].GroupID },
		func(train, val []Observation) { val[0].SessionID = train[0].SessionID },
		func(train, val []Observation) { val[0].Class = ClassBelNet },
		func(train, val []Observation) { val[0].Split = SplitTest },
		func(train, val []Observation) { train[0].Events = nil },
		func(train, val []Observation) { train[0].Events[0].Direction = 0 },
		func(train, val []Observation) { train[1].SessionID = train[0].SessionID },
	} {
		train, val := trainingData()
		mutate(train, val)
		if _, err := Fit(config, train, val); err == nil {
			t.Fatal("accepted leakage or invalid data")
		}
	}
}

func TestIdenticalTrafficDoesNotFakeDetectionImprovement(t *testing.T) {
	train, val := trainingData()
	for i := range train {
		train[i].Events = []Event{{0, 1, 100}, {1000, -1, 100}}
	}
	for i := range val {
		val[i].Events = []Event{{0, 1, 100}, {1000, -1, 100}}
	}
	m, err := Fit(TrainingConfig{Seed: 1, Trees: 12, Depth: 4, FPRBudget: .05}, train, val)
	if err != nil {
		t.Fatal(err)
	}
	metrics := Evaluate(m, train)
	if metrics.TPR != 0 || metrics.FPR != 0 {
		t.Fatalf("fabricated separation on identical traffic: %+v", metrics)
	}
}

func TestLoadRejectsMalformedModels(t *testing.T) {
	train, val := trainingData()
	m, err := Fit(TrainingConfig{Seed: 1, Trees: 2, Depth: 2, FPRBudget: .05}, train, val)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Model){
		func(m *Model) { m.SchemaVersion++ },
		func(m *Model) { m.FeatureNames[0] = "ip_address" },
		func(m *Model) { m.Trees[0].Nodes[0] = Node{Left: 0, Right: 0} },
		func(m *Model) { m.Trees[0].Nodes[0].Probability = 2 },
	} {
		data, _ := json.Marshal(m)
		var copy Model
		_ = json.Unmarshal(data, &copy)
		mutate(&copy)
		bad, _ := json.Marshal(copy)
		if _, err := Load(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted invalid model")
		}
	}
	var valid bytes.Buffer
	_ = m.Save(&valid)
	if _, err := Load(bytes.NewReader(append(valid.Bytes(), []byte("{}")...))); err == nil {
		t.Fatal("accepted trailing model")
	}
	if math.IsNaN(m.Score(example(ClassBelNet, SplitTest, 0))) {
		t.Fatal("nonfinite score")
	}
}

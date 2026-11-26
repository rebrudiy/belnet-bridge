package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("use fit, evaluate or version")
	}
	if args[0] == "catalog" {
		flags := flag.NewFlagSet("catalog", flag.ContinueOnError)
		engine := flags.String("engine", "", "pinned existing15 rule score CLI")
		order := flags.String("ordering-sha", "", "ordering contract SHA")
		coverage := flags.String("coverage-sha", "", "coverage contract SHA")
		recipes := flags.String("recipes", "", "optional explicit engineer-authored rules JSON array")
		output := flags.String("out", "", "combinedcatalog output")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *engine == "" || *output == "" || !hexSHA(*order) || !hexSHA(*coverage) {
			return fmt.Errorf("-engine -ordering-sha -out required")
		}
		work, err := os.MkdirTemp("", "ensemble-catalog-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		c, err := catalog(*engine, work)
		if err != nil {
			return err
		}
		combined, err := combinedCatalogCoverage(c, longDefinitionsSHA, *order, *coverage)
		if err != nil {
			return err
		}
		if *recipes != "" {
			var manual []EngineeredRule
			if _, err := read(*recipes, &manual); err != nil {
				return err
			}
			combined, err = engineeredCatalog(combined, manual)
			if err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Dir(*output), 0700); err != nil {
			return err
		}
		return write(*output, combined)
	}
	if args[0] == "version" {
		fmt.Println(DefenderVersion)
		return nil
	}
	if args[0] != "fit" && args[0] != "evaluate" {
		return fmt.Errorf("use fit or evaluate")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	index := fs.String("index", "", "schema4 typed stage-matched observer index")
	freezePath := fs.String("freeze", "", "G03 defender freeze projection")
	engine := fs.String("engine", "out/dpi-g03/tooling-defender/classical", "pinned unchanged15-rule score CLI")
	output := fs.String("out", "", "output JSON")
	policyPath := fs.String("policy", "", "frozen B1 policy for evaluation")
	work := fs.String("work", "out/dpi-g03/tooling-defender/work", "private score workspace")
	budget := fs.Float64("budget", .05, "frozen joint group/direct-flow FPR budget")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *index == "" || *freezePath == "" || *output == "" {
		return fmt.Errorf("-index -freeze -out required")
	}
	reject := func(err error, groups []Group) error {
		_ = write(*output+".rejected.json", map[string]any{"schema": 4, "error": err.Error(), "groups": groups, "no_successful_fit_or_evaluation": true})
		return err
	}
	var f Freeze
	freezeSHA, err := read(*freezePath, &f)
	if err != nil {
		return reject(err, nil)
	}
	if err = validateFreeze(f); err != nil {
		return reject(err, nil)
	}
	if *budget != f.Budget {
		return reject(fmt.Errorf("CLI budget cannot change frozen5%% budgets"), nil)
	}
	selfPath, selfErr := os.Executable()
	if selfErr != nil {
		return reject(selfErr, nil)
	}
	self, selfErr := os.ReadFile(selfPath)
	if selfErr != nil || sha(self) != f.EnsembleSHA {
		return reject(fmt.Errorf("ensemble executable SHA mismatch"), nil)
	}
	isFit := args[0] == "fit"
	// Index preflight, complete metadata loading and chronology gates run before
	// engine invocation; B1 cannot read test report paths or produce their scores.
	groups, err := loadGroups(*index, f, freezeSHA, isFit)
	if err != nil {
		return reject(err, nil)
	}
	var p Policy
	policySHA := ""
	if !isFit {
		policySHA, err = read(*policyPath, &p)
		if err != nil {
			return reject(err, groups)
		}
		if err = policyBinding(p, f, freezeSHA, policySHA); err != nil {
			return reject(err, groups)
		}
		if err = validateTestChronology(groups, p); err != nil {
			return reject(err, groups)
		}
	} else if problems := groupErrors(groups); len(problems) > 0 {
		return reject(fmt.Errorf("incomplete calibration groups (all failures): %v", problems), groups)
	}
	raw, err := os.ReadFile(*engine)
	if err != nil {
		return reject(err, groups)
	}
	if sha(raw) != f.EngineSHA {
		return reject(fmt.Errorf("score engine SHA mismatch"), groups)
	}
	if err = os.MkdirAll(*work, 0700); err != nil {
		return reject(err, groups)
	}
	scratch, err := os.MkdirTemp(*work, "g03-session-or-")
	if err != nil {
		return reject(err, groups)
	}
	defer os.RemoveAll(scratch)
	windowCatalog, err := catalog(*engine, scratch)
	if err != nil {
		return reject(err, groups)
	}
	if windowCatalog.SHA != f.WindowDefinitionsSHA {
		return reject(fmt.Errorf("definitions SHA mismatch"), groups)
	}
	baseCatalog, err := combinedCatalogCoverage(windowCatalog, f.LongflowDefinitionsSHA, f.OrderingSHA, f.CoverageSHA)
	if err != nil {
		return reject(err, groups)
	}
	c, err := engineeredCatalog(baseCatalog, f.EngineeredRules)
	if err != nil {
		return reject(err, groups)
	}
	if c.SHA != f.DefinitionsSHA {
		return reject(fmt.Errorf("combined definitions SHA mismatch"), groups)
	}
	if !isFit {
		if p.DefinitionsSHA != c.SHA || p.EngineSHA != f.EngineSHA {
			return reject(fmt.Errorf("policy score-engine provenance mismatch"), groups)
		}
		if err = validatePolicy(p, c, f); err != nil {
			return reject(err, groups)
		}
	}
	if err = scoreGroups(groups, *engine, scratch, windowCatalog); err != nil {
		return reject(err, groups)
	}
	afterEngine, afterErr := os.ReadFile(*engine)
	if afterErr != nil || sha(afterEngine) != f.EngineSHA {
		return reject(fmt.Errorf("score engine changed during scoring"), groups)
	}
	applyOrderingMasks(groups)
	addCaptureOrderScores(groups)
	if err = appendLongflow(groups, *index, f); err != nil {
		return reject(err, groups)
	}
	addEngineeredScores(groups, f.EngineeredRules)
	if err = finiteScores(groups); err != nil {
		return reject(err, groups)
	}
	if isFit {
		p, err = calibrate(groups, c, f, freezeSHA, *budget)
		if err != nil {
			return reject(err, groups)
		}
		for _, g := range groups {
			if g.Metadata.CaptureEnded.After(p.LastDevelopmentCapture) {
				p.LastDevelopmentCapture = g.Metadata.CaptureEnded
			}
		}
		p.FrozenAt = time.Now().UTC()
		if !p.FrozenAt.After(p.LastDevelopmentCapture) {
			return reject(fmt.Errorf("policy wall UTC not after development VM capture; use a clock-consistent host"), groups)
		}
		if err = write(*output, p); err != nil {
			return err
		}
		if err = write(*output+".calibration.json", groups); err != nil {
			return err
		}
		fmt.Printf("B1 frozen policy: %d groups, %d enabled/%d effective rules; jointly calibrated across base23 plus frozen explicit engineered rules, primary windows/whole-flows/reconnects\n", len(groups), p.EnabledRules, p.EffectiveRules)
		return nil
	}
	ds := evaluate(groups, p)
	bySplit := map[string][]Decision{}
	byProfile := map[string][]Decision{}
	byStack := map[string][]Decision{}
	for _, d := range ds {
		bySplit[d.Split] = append(bySplit[d.Split], d)
		byProfile[d.Profile] = append(byProfile[d.Profile], d)
		byStack[d.ClientStack] = append(byStack[d.ClientStack], d)
	}
	splits, profiles, stacks := map[string]Calibration{}, map[string]Calibration{}, map[string]Calibration{}
	for name, d := range bySplit {
		splits[name] = measure(d)
	}
	for name, d := range byProfile {
		profiles[name] = measure(d)
	}
	for name, d := range byStack {
		stacks[name] = measure(d)
	}
	scope := "B1 development train/validation, not heldout evidence"
	if f.Stage == "B2" {
		scope = "B2 fresh capture after exact policy freeze; finite correlated session cohort"
	}
	status := "complete_finite_cohort"
	if len(groupErrors(groups)) > 0 {
		status = "coverage_incomplete_observed_detection_lower_bound"
	}
	if err = write(*output, map[string]any{"schema": 4, "version": DefenderVersion, "stage": f.Stage, "scope": scope, "status": status, "coverage_errors": groupErrors(groups), "policy_sha256": policySHA, "evaluation_freeze_sha256": freezeSHA, "policy": p, "all": measure(ds), "by_split": splits, "by_profile": profiles, "by_client_stack": stacks, "decisions": ds, "source_cluster_metrics": sourceClusters(ds), "physical_sessions_iid": false, "scored_groups": groups, "persistent_blocking_scope": "Offline OR only. Direct rule-hit flow FP excludes IP-ban collateral;30s persistence execution not simulated here."}); err != nil {
		return err
	}
	fmt.Printf("%s evaluated %d groups; missing/censored groups remain unknown, abstention is not stealth\n", f.Stage, len(groups))
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

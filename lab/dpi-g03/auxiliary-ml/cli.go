package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("use catalog, fit, evaluate or version")
	}
	if args[0] == "version" {
		fmt.Println(Version)
		return nil
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	freezePath := fs.String("freeze", "", "auxiliary freeze projection")
	indexPath := fs.String("index", "", "shared schema4 typed observer index")
	out := fs.String("out", "", "output JSON")
	policyPath := fs.String("policy", "", "frozen auxiliary policy for evaluate")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out required")
	}
	if args[0] == "catalog" {
		return write(*out, map[string]any{"schema": 1, "role": Role, "version": Version, "definitions_sha256": definitionsSHA(), "contract": featureContract()})
	}
	if args[0] != "fit" && args[0] != "evaluate" {
		return fmt.Errorf("use fit or evaluate")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("refusing to overwrite auxiliary model/report")
	}
	if *freezePath == "" || *indexPath == "" {
		return fmt.Errorf("-freeze -index required")
	}
	reject := func(err error, groups []Group) error {
		_ = write(*out+".rejected.json", map[string]any{"schema": 1, "role": Role, "error": err.Error(), "groups": groups, "no_successful_fit_or_evaluation": true})
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
	fit := args[0] == "fit"
	if err = releaseGate(f, *freezePath, fit); err != nil {
		return reject(err, nil)
	} // BEFORE index and observer-report reads.
	self, err := os.Executable()
	if err != nil {
		return reject(err, nil)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		return reject(err, nil)
	}
	if sha(binary) != f.AuxiliarySHA {
		return reject(fmt.Errorf("auxiliary executable SHA mismatch"), nil)
	}
	var p Policy
	policySHA := ""
	if !fit {
		policySHA, err = read(*policyPath, &p)
		if err != nil {
			return reject(err, nil)
		}
		if err = validatePolicy(p); err != nil {
			return reject(err, nil)
		}
		if err = policyBinding(p, f, freezeSHA, policySHA); err != nil {
			return reject(err, nil)
		}
	}
	groups, err := loadGroups(*indexPath, f, freezeSHA, fit)
	if err != nil {
		return reject(err, nil)
	}
	if err = releasedCaptureClock(f, *freezePath, groups); err != nil {
		return reject(err, groups)
	}
	if fit {
		if failures := groupErrors(groups); len(failures) > 0 {
			return reject(fmt.Errorf("incomplete calibration cohort: %v", failures), groups)
		}
	}
	if fit {
		p, err = fitAuxiliary(groups, f, freezeSHA)
		if err != nil {
			return reject(err, groups)
		}
		p.FrozenAt = time.Now().UTC()
		if !p.FrozenAt.After(p.LastDevelopmentCapture) {
			return reject(fmt.Errorf("auxiliary final policy clock not after development captures"), groups)
		}
		if err = validatePolicy(p); err != nil {
			return reject(err, groups)
		}
		if err = write(*out, p); err != nil {
			return err
		}
		if err = write(*out+".calibration.json", groups); err != nil {
			return err
		}
		fmt.Printf("AUXILIARY only; trainwindows=%d disabled=%v; separatejointgroup+flow threshold%.8f\n", p.TrainingWindows, p.Disabled, p.Threshold)
		return nil
	}
	if err = testChronology(groups, p); err != nil {
		return reject(err, groups)
	}
	ds := evaluate(groups, p)
	m := measure(ds)
	status := "AUXILIARY_finite_cohort"
	if m.Incomplete > 0 {
		status = "AUXILIARY_INCONCLUSIVE_incomplete"
	} else if p.Disabled || m.EligibleWindows == 0 || m.EligibleBenign == 0 || m.EligiblePositive == 0 || m.EligibleWindows*2 < m.Windows || m.EligibleBenign*2 < m.Benign || m.EligiblePositive*2 < m.Positive {
		status = "AUXILIARY_INCONCLUSIVE_support_or_disabled"
	}
	if err = write(*out, map[string]any{"schema": 1, "role": Role, "version": Version, "status": status, "stage": f.Stage, "policy_sha256": policySHA, "freeze_sha256": freezeSHA, "policy": p, "all": m, "by_split": metricsBy(ds, func(d Decision) string { return d.Split }), "by_class": metricsBy(ds, func(d Decision) string { return d.Class }), "by_client_stack": metricsBy(ds, func(d Decision) string { return d.ClientStack }), "by_class_stack": metricsBy(ds, func(d Decision) string { return d.Class + "/" + d.ClientStack }), "by_profile": metricsBy(ds, func(d Decision) string { return d.Profile }), "decisions": ds, "coverage_errors": groupErrors(groups), "combination_scope": "Standalone auxiliary own5% calibration only. No OR with classical inherits5%. Valid auxiliary detection can refute a blanket bypass claim even if classical misses.", "physical_scope": "Canonical capture-time sensor metadata only, no physical request/reply causality, no ISP guarantee."}); err != nil {
		return err
	}
	fmt.Printf("%s groups=%d eligiblewindows=%d; no combined-classical FPR claim\n", status, m.Groups, m.EligibleWindows)
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

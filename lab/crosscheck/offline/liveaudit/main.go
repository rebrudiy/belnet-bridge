// Command liveaudit independently replays frozen-model decisions and counters.
// Source acquisition data, model, threshold and trial files are read-only.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rebrudiy/belnet-bridge/internal/traffic"
)

type proof struct {
	OK        bool   `json:"ok"`
	Nonce     string `json:"nonce"`
	BodyBytes int    `json:"body_bytes"`
	ElapsedMS int64  `json:"elapsed_ms"`
}
type decision struct {
	Time             string          `json:"time"`
	StartedAt        string          `json:"started_at"`
	SessionID        string          `json:"session_id"`
	ConnectionID     string          `json:"connection_id"`
	TrialID          string          `json:"trial_id"`
	Mode             string          `json:"mode"`
	MetadataError    string          `json:"metadata_error"`
	ModelSHA         string          `json:"model_sha256"`
	ModelArtifactSHA string          `json:"model_artifact_sha256"`
	Score            float64         `json:"score"`
	Blocked          bool            `json:"blocked"`
	Complete         bool            `json:"complete"`
	Enforced         bool            `json:"enforced"`
	Malformed        bool            `json:"malformed"`
	Events           []traffic.Event `json:"events"`
	Records          int             `json:"records"`
	Termination      string          `json:"termination"`
}
type trial struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Mode          string     `json:"mode"`
	BodyBytes     int        `json:"body_bytes"`
	Proof         proof      `json:"proof"`
	After         *proof     `json:"after_window_proof"`
	Decisions     []decision `json:"decisions"`
	CompleteFlows int        `json:"complete_flows"`
	FlaggedFlows  int        `json:"flagged_flows"`
	EnforcedFlows int        `json:"enforced_flows"`
	CompleteGroup bool       `json:"complete_group"`
	Error         string     `json:"error"`
}
type counters struct {
	Groups          int `json:"groups"`
	CompleteGroups  int `json:"complete_groups"`
	DetectedGroups  int `json:"detected_groups"`
	CompleteFlows   int `json:"complete_flows"`
	FlaggedFlows    int `json:"flagged_flows"`
	EnforcedFlows   int `json:"enforced_flows"`
	IncompleteFlows int `json:"incomplete_flows"`
	ProofSuccess    int `json:"initial_proof_success"`
	AfterSuccess    int `json:"after_window_proof_success"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func main() {
	if len(os.Args) < 4 || len(os.Args) > 6 {
		panic("usage: liveaudit MODEL_JSON LIVE_DIR OUTPUT_JSON [SERVICE_LOG] [CLAUDE_RAW_DECISIONS_JSONL]")
	}
	modelData, err := os.ReadFile(os.Args[1])
	must(err)
	model, err := traffic.Load(bytes.NewReader(modelData))
	must(err)
	canonical, err := json.Marshal(model)
	must(err)
	modelArtifactSHA, modelSHA := digest(modelData), digest(canonical)
	directory := os.Args[2]
	errors := []string{}
	coverage := []string{}
	counts := map[string]*counters{}
	hashes := map[string]string{}
	rows := []map[string]any{}
	allDecisions := map[string]string{}
	nonceExpected := map[string]int{}
	expectedIDs := map[string]bool{}
	maxDelta := 0.0
	scored := 0
	checkDecision := func(d decision, mode, location string) {
		if d.ModelSHA != modelSHA {
			errors = append(errors, location+": model canonical SHA mismatch")
		}
		if d.ModelArtifactSHA != "" && d.ModelArtifactSHA != modelArtifactSHA {
			errors = append(errors, location+": model artifact SHA mismatch")
		}
		if d.Records != len(d.Events) || len(d.Events) > traffic.MaxRecords {
			errors = append(errors, location+": record count mismatch")
		}
		var previous int64
		for i, e := range d.Events {
			if e.AtMicros < 0 || e.AtMicros >= traffic.Window.Microseconds() || (i > 0 && e.AtMicros < previous) || (i == 0 && e.AtMicros != 0) || (e.Direction != 1 && e.Direction != -1) || e.Bytes < 5 || e.Bytes > 65540 {
				errors = append(errors, location+": invalid encrypted record event")
			}
			previous = e.AtMicros
		}
		if d.Complete {
			if len(d.Events) == 0 || d.Malformed {
				errors = append(errors, location+": invalid complete observation")
			}
			o := traffic.Observation{Events: d.Events}
			actual := model.Score(o)
			delta := math.Abs(actual - d.Score)
			maxDelta = math.Max(maxDelta, delta)
			scored++
			if delta > 1e-12 || model.Block(o) != d.Blocked {
				errors = append(errors, location+": replay score/verdict mismatch")
			}
			if d.StartedAt != "" && len(d.Events) < traffic.MaxRecords {
				start, e1 := time.Parse(time.RFC3339Nano, d.StartedAt)
				end, e2 := time.Parse(time.RFC3339Nano, d.Time)
				if e1 != nil || e2 != nil || end.Sub(start) < traffic.Window {
					errors = append(errors, location+": complete decision before full window")
				}
			}
		} else if d.Score != 0 || d.Blocked || d.Enforced {
			errors = append(errors, location+": incomplete observation improperly classified/enforced")
		}
		expectedEnforcement := d.Complete && mode == "enforce" && d.Blocked && d.Termination == "window_complete"
		if d.Enforced != expectedEnforcement {
			errors = append(errors, location+": enforcement predicate mismatch")
		}
	}
	sizes := []int{1024, 4096, 16384, 1024, 4096, 16384, 1024, 4096}
	for _, mode := range []string{"shadow", "enforce"} {
		for _, kind := range []string{"ours", "claude"} {
			n := 8
			if mode == "enforce" {
				n = 2
			}
			key := kind + "-" + mode
			stats := &counters{}
			counts[key] = stats
			for i := 1; i <= n; i++ {
				id := fmt.Sprintf("%s-%02d", key, i)
				expectedIDs[id] = true
				file := filepath.Join(directory, id+".json")
				data, e := os.ReadFile(file)
				if e != nil {
					coverage = append(coverage, id+": missing trial file")
					continue
				}
				hashes[filepath.Base(file)] = digest(data)
				var t trial
				must(json.Unmarshal(data, &t))
				stats.Groups++
				if t.ID != id || t.Kind != kind || t.Mode != mode {
					errors = append(errors, id+": trial identity mismatch")
				}
				if t.BodyBytes != sizes[i-1] {
					errors = append(errors, id+": preregistered body schedule mismatch")
				}
				complete, flagged, enforced, incomplete := 0, 0, 0, 0
				localIDs := map[string]bool{}
				for j, d := range t.Decisions {
					location := fmt.Sprintf("%s decision%d", id, j)
					checkDecision(d, mode, location)
					uid := d.SessionID
					if kind == "claude" {
						uid = d.ConnectionID
					}
					if uid == "" {
						errors = append(errors, location+": missing connection identity")
					}
					if localIDs[uid] {
						errors = append(errors, location+": duplicate connection within trial")
					}
					localIDs[uid] = true
					if prior, ok := allDecisions[uid]; ok && prior != id {
						errors = append(errors, location+": same connection assigned across trials")
					}
					allDecisions[uid] = id
					if kind == "claude" && (d.TrialID != id || d.Mode != mode || d.MetadataError != "") {
						errors = append(errors, location+": invalid trial provenance")
					}
					if d.Complete {
						complete++
						if d.Blocked {
							flagged++
						}
					} else {
						incomplete++
					}
					if d.Enforced {
						enforced++
					}
				}
				required := 1
				if kind == "ours" {
					required = 2
				}
				full := complete >= required
				if t.CompleteFlows != complete || t.FlaggedFlows != flagged || t.EnforcedFlows != enforced || t.CompleteGroup != full {
					errors = append(errors, id+": published aggregate counters mismatch")
				}
				if !full {
					coverage = append(coverage, id+": incomplete group coverage; not successful evasion")
				}
				if t.Error != "" {
					coverage = append(coverage, id+": acquisition error: "+t.Error)
				}
				if full {
					stats.CompleteGroups++
				}
				if flagged > 0 {
					stats.DetectedGroups++
				}
				stats.CompleteFlows += complete
				stats.FlaggedFlows += flagged
				stats.EnforcedFlows += enforced
				stats.IncompleteFlows += incomplete
				addProof := func(p proof, requested int, label string) {
					if !p.OK {
						return
					}
					if len(p.Nonce) != 64 || p.BodyBytes != requested {
						errors = append(errors, label+": malformed successful proof")
					}
					if _, ok := nonceExpected[p.Nonce]; ok {
						errors = append(errors, label+": duplicate successful nonce")
					}
					nonceExpected[p.Nonce] = p.BodyBytes
				}
				addProof(t.Proof, t.BodyBytes, id+" initial")
				if t.Proof.OK {
					stats.ProofSuccess++
				}
				if mode == "enforce" {
					if t.After == nil {
						coverage = append(coverage, id+": after-window proof missing")
					} else {
						addProof(*t.After, 4096, id+" after")
						if t.After.OK {
							stats.AfterSuccess++
						}
					}
				}
				rows = append(rows, map[string]any{"id": id, "complete_flows": complete, "flagged_flows": flagged, "enforced_flows": enforced, "incomplete_flows": incomplete, "complete_group": full, "initial_proof_ok": t.Proof.OK, "after_window_proof_ok": t.After != nil && t.After.OK})
			}
		}
	}

	// Supplemental explicit confirmation never replaces missing original coverage.
	confirmation := map[string]any{"provided": false}
	confirmationPath := filepath.Join(directory, "claude-enforce-confirmation.json")
	if data, e := os.ReadFile(confirmationPath); e == nil {
		hashes[filepath.Base(confirmationPath)] = digest(data)
		var t trial
		must(json.Unmarshal(data, &t))
		confirmation["provided"] = true
		confirmation["id"] = t.ID
		confirmation["separate_from_original_groups"] = true
		complete, flagged, enforced := 0, 0, 0
		for i, d := range t.Decisions {
			checkDecision(d, "enforce", fmt.Sprintf("confirmation decision%d", i))
			if d.TrialID != t.ID || d.Mode != "enforce" || d.MetadataError != "" {
				errors = append(errors, "confirmation decision provenance invalid")
			}
			if d.Complete {
				complete++
				if d.Blocked {
					flagged++
				}
			}
			if d.Enforced {
				enforced++
			}
		}
		add := func(p proof) {
			if !p.OK {
				return
			}
			if len(p.Nonce) != 64 || p.BodyBytes != 4096 {
				errors = append(errors, "malformed supplemental successful proof")
			}
			if _, ok := nonceExpected[p.Nonce]; ok {
				errors = append(errors, "duplicate supplemental successful nonce")
			}
			nonceExpected[p.Nonce] = p.BodyBytes
		}
		add(t.Proof)
		if t.After != nil {
			add(*t.After)
		}
		confirmation["complete_flows"] = complete
		confirmation["flagged_flows"] = flagged
		confirmation["enforced_flows"] = enforced
		confirmation["initial_proof_ok"] = t.Proof.OK
		confirmation["after_window_proof_ok"] = t.After != nil && t.After.OK
	}
	// Fresh synthetic controls are scored independently with the same frozen model.
	benign := map[string]any{"groups": 0, "complete_flows": 0, "flagged_flows": 0, "echo_groups_ok": 0}
	for i := 1; i <= 8; i++ {
		id := fmt.Sprintf("cross-benign-%02d", i)
		path := filepath.Join(directory, id+".json")
		data, e := os.ReadFile(path)
		if e != nil {
			continue
		}
		hashes[filepath.Base(path)] = digest(data)
		var b struct {
			ID        string     `json:"id"`
			Decisions []decision `json:"server_decisions"`
			Result    struct {
				Echo struct {
					SentFrames     int `json:"sent_frames"`
					ReceivedFrames int `json:"received_frames"`
					SentBytes      int `json:"sent_bytes"`
					ReceivedBytes  int `json:"received_bytes"`
				} `json:"echo"`
			} `json:"result"`
		}
		must(json.Unmarshal(data, &b))
		if b.ID != id {
			errors = append(errors, id+": benign identity mismatch")
		}
		benign["groups"] = benign["groups"].(int) + 1
		for j, d := range b.Decisions {
			checkDecision(d, "shadow", fmt.Sprintf("%s decision%d", id, j))
			if d.Complete {
				benign["complete_flows"] = benign["complete_flows"].(int) + 1
				if d.Blocked {
					benign["flagged_flows"] = benign["flagged_flows"].(int) + 1
				}
			}
		}
		echo := b.Result.Echo
		if echo.SentFrames > 0 && echo.SentFrames == echo.ReceivedFrames && echo.SentBytes == echo.ReceivedBytes {
			benign["echo_groups_ok"] = benign["echo_groups_ok"].(int) + 1
		} else {
			errors = append(errors, id+": benign echo delivery incomplete")
		}
	}
	// Bind OUR connection IDs back to the two retained original entry snapshots.
	entryMap := map[string]int{}
	for entry := 1; entry <= 2; entry++ {
		path := filepath.Join(directory, fmt.Sprintf("our-entry%d-decisions.json", entry))
		if data, e := os.ReadFile(path); e == nil {
			var value struct {
				Decisions []decision `json:"decisions"`
			}
			must(json.Unmarshal(data, &value))
			hashes[filepath.Base(path)] = digest(data)
			for _, d := range value.Decisions {
				if d.SessionID != "" {
					if prior, ok := entryMap[d.SessionID]; ok && prior != entry {
						errors = append(errors, "connection ID seen on both entry snapshots")
					}
					entryMap[d.SessionID] = entry
				}
			}
		}
	}
	entryCoverage := []map[string]any{}
	for _, mode := range []string{"shadow", "enforce"} {
		n := 8
		if mode == "enforce" {
			n = 2
		}
		for i := 1; i <= n; i++ {
			id := fmt.Sprintf("ours-%s-%02d", mode, i)
			data, e := os.ReadFile(filepath.Join(directory, id+".json"))
			if e != nil {
				continue
			}
			var t trial
			must(json.Unmarshal(data, &t))
			seen := map[int]bool{}
			for _, d := range t.Decisions {
				if d.Complete {
					if entry := entryMap[d.SessionID]; entry != 0 {
						seen[entry] = true
					}
				}
			}
			both := seen[1] && seen[2]
			entryCoverage = append(entryCoverage, map[string]any{"trial": id, "both_distinct_entries_complete": both})
			if !both {
				errors = append(errors, id+": distinct entry coverage not proven")
			}
		}
	}

	// Raw Claude records reveal unassigned/tail connections; never discard them as evasion.
	rawSummary := map[string]any{"provided": false}
	if len(os.Args) >= 6 {
		data, e := os.ReadFile(os.Args[5])
		must(e)
		rawSummary["provided"] = true
		rawSummary["file_sha256"] = digest(data)
		invalid := []map[string]any{}
		extra := []map[string]any{}
		rawRows := 0
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var d decision
			must(json.Unmarshal(line, &d))
			rawRows++
			checkDecision(d, d.Mode, "raw Claude "+d.ConnectionID)
			compact := map[string]any{"connection_id": d.ConnectionID, "trial_id": d.TrialID, "mode": d.Mode, "complete": d.Complete, "blocked": d.Blocked, "enforced": d.Enforced, "metadata_error": d.MetadataError}
			if d.MetadataError != "" || d.TrialID == "" {
				invalid = append(invalid, compact)
			} else if !expectedIDs[d.TrialID] {
				extra = append(extra, compact)
			}
		}
		rawSummary["rows"] = rawRows
		rawSummary["invalid_metadata_connections"] = invalid
		rawSummary["separately_labelled_extra_connections"] = extra
	}
	nonceSummary := map[string]any{"successful_unique_trial_nonces": len(nonceExpected), "service_log_provided": false}
	if len(os.Args) >= 5 {
		data, e := os.ReadFile(os.Args[4])
		must(e)
		nonceSummary["service_log_provided"] = true
		nonceSummary["service_log_sha256"] = digest(data)
		pattern := regexp.MustCompile(`proof nonce=([0-9a-f]{64}) bytes=([0-9]+)`)
		found := map[string][]int{}
		for _, m := range pattern.FindAllStringSubmatch(string(data), -1) {
			n, e := strconv.Atoi(m[2])
			must(e)
			found[m[1]] = append(found[m[1]], n)
		}
		matched := 0
		missing := []string{}
		for nonce, expected := range nonceExpected {
			values := found[nonce]
			if len(values) == 1 && values[0] == expected {
				matched++
			} else {
				missing = append(missing, nonce)
			}
		}
		sort.Strings(missing)
		nonceSummary["exact_unique_service_joins"] = matched
		nonceSummary["missing_or_nonunique_nonce_joins"] = missing
		if len(missing) > 0 {
			errors = append(errors, "successful trial nonce service joins missing/nonunique")
		}
	}
	// Frozen file is checked again after all scoring.
	again, e := os.ReadFile(os.Args[1])
	must(e)
	if !bytes.Equal(again, modelData) {
		errors = append(errors, "model bytes changed during audit")
	}
	output := map[string]any{"model_artifact_sha256": modelArtifactSHA, "model_canonical_sha256": modelSHA, "threshold": model.Threshold, "training_or_recalibration": false, "trial_files": hashes, "groups": counts, "trial_details": rows, "unique_trial_decision_connections": len(allDecisions), "score_replays_including_raw_duplicates": scored, "max_score_difference": maxDelta, "raw_claude": rawSummary, "supplemental_confirmation": confirmation, "new_benign_controls": benign, "distinct_our_entry_coverage": entryCoverage, "proof_audit": nonceSummary, "coverage_notes": coverage, "errors": errors, "evidence_integrity_pass": len(errors) == 0, "original_group_coverage_complete": len(coverage) == 0, "notes": []string{"Complete-group counter reproduces original >=2 ours / >=1 Claude rule; distinct OUR entry identity needs separate raw entry snapshots/PCAP join.", "New benign controls are eight synthetic Go TLS workload groups, not a representative browser HTTPS population; no general false-positive claim.", "Actual TCP closure and delivered HTTP proof are separate outcomes.", "Raw extra confirmations/tail records are retained separately; incomplete original groups are not silently replaced."}}
	encoded, e := json.MarshalIndent(output, "", "  ")
	must(e)
	must(os.WriteFile(os.Args[3], append(encoded, '\n'), 0600))
	fmt.Printf("Live audit: integrity=%v; score difference=%.15g; coverage notes=%d; unique proofs=%d\n", len(errors) == 0, maxDelta, len(coverage), len(nonceExpected))
	if len(errors) > 0 {
		fmt.Println(strings.Join(errors, "\n"))
		os.Exit(1)
	}
}

"use strict";
// Independent acquisition review for a real adaptive round, using the R4 sensor.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { inspectGroup } = require("./review-r4.cjs");
const { pinLocation } = require("./review-checkpoint.cjs");
const { verifyPreparation } = require("./review-analysis-r4.cjs");
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
function guardRound(f) {
  if (f.schema !== "belnet-g03-collector/v4" || f.stage !== "B1" || !Number.isInteger(f.adaptive_round) || f.adaptive_round < 1 || f.adaptive_round > 15 || f.experiment_role !== "candidate-development") throw Error("explicit_adaptive_development_round_required");
  if (![3, 6].includes(f.groups?.length) || new Set(f.groups.map(g => g.group_id)).size !== f.groups.length) throw Error("three_or_six_distinct_native_groups_required");
  const nonces = new Set();
  for (const g of f.groups) {
    if (!/^b-(train|validation)-native-[a-z0-9-]+$/.test(g.group_id) || !["train", "validation"].includes(g.split) || g.scope !== "primary" || g.class !== "belnet" || g.stratum !== "native" || g.experiment_role !== f.experiment_role || g.adaptive_round !== f.adaptive_round || g.fresh_native_identity_required !== true || !["rpc", "download", "upload"].includes(g.family)) throw Error("native_primary_train_validation_only");
    if (!Number.isSafeInteger(g.seed_int) || g.seed_int < 1 || g.seed_int >= 2 ** 48 || !Array.isArray(g.warmup_nonces) || g.warmup_nonces.length !== 3) throw Error("native_seed_and_five_nonce_attempts_required");
    for (const value of [g.nonce, g.initial_nonce, ...g.warmup_nonces]) {
      if (!/^[a-f0-9]{64}$/.test(value || "") || nonces.has(value)) throw Error("unique_fresh_nonces_required");
      nonces.add(value);
    }
  }
  if (!["train", "validation"].every(split => f.groups.some(g => g.split === split)) || !["rpc", "download", "upload"].every(family => f.groups.filter(g => g.family === family).length === f.groups.length / 3)) throw Error("all_three_native_families_and_both_development_splits_required");
  if (!Array.isArray(f.batches) || f.batches.length !== f.groups.length || f.batches.some(b => b.length !== 1) || f.batches.flat().join(",") !== f.groups.map(g => g.group_id).join(",")) throw Error("one_native_at_a_time_in_frozen_order");
  if (f.capture_mode !== "buffered" || f.capture_buffer_kib !== 16384 || f.measured_seconds !== 80 || f.capture_seconds !== 82 || f.stats_drain_budget_ms !== 2500 || f.stats_stable_ms !== 100 || f.quiesce_drain_micros !== 500000 || !Object.keys(f.files_sha256 || {}).length) throw Error("qualified_R4_sensor_and_nonempty_source_pins_required");
}
function qualifyRoundResults({ terminal, missing, errors, groups }) {
  const nonsemanticFailures = groups.flatMap(g => g.errors.filter(e => e !== "reporter_coverage_unknown").map(error => ({ group_id: g.group_id, error })));
  return { nonsemanticFailures, rawQualified: terminal && !missing.length && !errors.length && !nonsemanticFailures.length };
}
function audit(directory, freezePath) {
  let forbidden = null;
  const inputs = {}, read = file => { if (forbidden && path.resolve(file) === forbidden) throw Error("private_test_reference_rejected_before_read"); const raw = fs.readFileSync(file); inputs[path.resolve(file)] = hash(raw); return raw; };
  const raw = read(freezePath), f = JSON.parse(raw); guardRound(f);
  if (typeof f.test_seeds_commitment?.path !== "string") throw Error("original_test_commitment_metadata_required_without_values");
  forbidden = path.resolve(f.test_seeds_commitment.path);
  const errors = [], pins = [], groups = [], missing = [];
  for (const [file, expected] of Object.entries(f.files_sha256)) {
    const location = pinLocation(f, file), actual = hash(read(location.filename));
    pins.push({ path: file, matches: actual === expected }); if (actual !== expected) errors.push("source_pin_changed:" + file);
  }
  const prepared = verifyPreparation(f, read), prep = JSON.parse(read(f.prepared.path));
  if (prep.adaptive_candidate_only !== true || !prep.adapter_source_provenance?.candidate_manifest_sha256 || !prep.baseline_preparation?.sha256) throw Error("explicit_candidate_preparation_provenance_required");
  for (const g of f.groups) {
    const dir = path.join(directory, g.group_id);
    if (!fs.existsSync(path.join(dir, "result.json"))) { missing.push(g.group_id); continue; }
    groups.push(inspectGroup(...["result.json", "windows.json", "longflow.json"].map(name => JSON.parse(read(path.join(dir, name)))), read(path.join(dir, "outer.pcap")), g, f, hash(raw)));
  }
  let terminal = false;
  let completionFinishedUTC = null, restorationComplete = false;
  const completionPath = path.join(directory, "completion.json"), restorationPath = path.join(directory, "restoration.json");
  if (fs.existsSync(completionPath) && fs.existsSync(restorationPath)) {
    const c = JSON.parse(read(completionPath)), r = JSON.parse(read(restorationPath));
    terminal = c.attempted === f.groups.length && c.total === f.groups.length && !c.stopped_after_batch && r.all_restored === true;
    restorationComplete = r.all_restored === true;
    completionFinishedUTC = c.finished_utc;
  }
  const indexPath = path.join(directory, "observer-index.json");
  let observerIndex = null;
  if (terminal) {
    const bytes = read(indexPath), index = JSON.parse(bytes);
    if (index.schema !== 4 || index.stage !== "B1" || index.reports?.length !== f.groups.length || new Set(index.reports.map(r => r.group_id)).size !== f.groups.length || index.coverage_errors?.length || index.reports.some(r => {
      const g = f.groups.find(g => g.group_id === r.group_id);
      return !g || r.split !== g.split || r.path !== g.group_id + "/windows.json" || r.longflow_path !== g.group_id + "/longflow.json" || r.coverage_errors?.length;
    })) errors.push("exact_complete_typed_round_index_required");
    observerIndex = { path: path.resolve(indexPath), sha256: hash(bytes) };
  }
  const { rawQualified, nonsemanticFailures } = qualifyRoundResults({ terminal, missing, errors, groups });
  return { schema: "g03-root-adaptive-round-acquisition/v1", checked_utc: new Date().toISOString(), adaptive_round: f.adaptive_round, stage: "B1", experiment_role: f.experiment_role, frozen_collector_sha256: hash(raw), collector_freeze: { path: path.resolve(freezePath), sha256: hash(raw) }, observer_index: observerIndex, acquisition_qualified: terminal && !missing.length && !errors.length && groups.every(g => g.acquisition_qualified), raw_acquisition_qualified: rawQualified, analysis_input_allowed: rawQualified, semantic_only_unknown_allowed: true, semantic_unknown_groups: groups.filter(g => g.errors.includes("reporter_coverage_unknown")).map(g => g.group_id), nonsemantic_failures: nonsemanticFailures, terminal_completed: terminal, completion_finished_utc: completionFinishedUTC, restoration_complete: restorationComplete, expected_groups: f.groups.length, reviewed_groups: groups.length, missing_groups: missing, errors, pins, prepared, candidate_elf_sha256: prep.adapter.sha256, groups, input_sha256: inputs, auditor_sha256: hash(fs.readFileSync(__filename)), private_test_values_read: false, detector_fitting_performed: false, scope: "Acquisition only. Raw-only release permits exactly reporter_coverage_unknown for a declared new view; strict semantic verdicts remain. Native nonce delivery, costs and classical retest require their own evidence." };
}
if (require.main === module) {
  const [directory, freeze, output] = process.argv.slice(2); if (!output) throw Error("usage: node review-round.cjs RUN FROZEN_ROUND NEW_OUTPUT");
  const result = audit(directory, freeze); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ round: result.adaptive_round, strict_qualified: result.acquisition_qualified, raw_analysis_input_allowed: result.analysis_input_allowed, reviewed: result.reviewed_groups, expected: result.expected_groups, errors: result.errors, group_errors: result.groups.filter(g => g.errors.length).map(g => ({ group_id: g.group_id, errors: g.errors })) }));
  process.exitCode = result.analysis_input_allowed ? 0 : 2;
}
module.exports = { guardRound, audit, qualifyRoundResults };

"use strict";
const fs = require("node:fs"), crypto = require("node:crypto");
const { derive: deriveR3 } = require("./make-r3.cjs");
const { validate } = require("./make-assignments.cjs");
const sha = raw => crypto.createHash("sha256").update(raw).digest("hex");

function derive(mode, source, master, sensor, extraPlans = [], fresh, qualification = null) {
  if (!["qualification", "b1"].includes(mode)) throw Error("explicit_R4_mode_required");
  for (const plan of [source, ...extraPlans]) {
    for (const group of plan.groups || []) {
      if (group.split !== "test") continue;
      if (![group.seed_hex, group.seed_int, group.nonce, group.initial_nonce].every(v => v === null) || !Array.isArray(group.warmup_nonces) || group.warmup_nonces.length !== 3 || !group.warmup_nonces.every(v => v === null))
        throw Error("all_test_seed_and_nonce_fields_must_remain_sealed");
    }
  }
  if (sensor?.schema !== "g03-root-capture-stress-review/v1" || !sensor.qualified || sensor.errors?.length !== 0 || sensor.private_test_values_read !== false)
    throw Error("independent_capture_stress_review_required");
  const expected = sensor.selected === "buffered16" ? ["buffered", 16384] : sensor.selected === "immediate64" ? ["immediate", 65536] : [];
  if (expected.length !== 2 || sensor.capture_mode !== expected[0] || sensor.buffer_kib !== expected[1]) throw Error("review_capture_mode_mismatch");
  if (mode === "b1" && (qualification?.schema !== "g03-root-acquisition-review/v4" || qualification.stage !== "Q" || qualification.acquisition_qualified !== true || qualification.expected_groups !== 3 || qualification.reviewed_groups !== 3 || qualification.groups?.length !== 3 || !qualification.groups.every(g => g.acquisition_qualified)))
    throw Error("complete_independent_Q4_review_required_before_B1");
  const result = deriveR3(mode, source, master, extraPlans, fresh);
  result.capture_shutdown = {
    capture_mode: sensor.capture_mode,
    buffer_kib: sensor.buffer_kib,
    immediate_mode: sensor.capture_mode === "immediate",
    min_postquiesce_drain_micros: 500000,
    stats_observation_budget_ms: 2500,
    required_identical_healthy_stats: 2,
    final_statistics_required_after_stop_frontier: true,
    stats_semantics: "Live comma or multiline counters; final counters must be fresh after stop and equal raw PCAP records. SIGUSR1 does not flush capture."
  };
  result.capture_selection = {
    selected: sensor.selected,
    independent_auditor_sha256: sensor.auditor_sha256,
    source_input_sha256: sensor.input_sha256,
    scope: "Fixed two-case synthetic stress; prospective native/Chrome/idle Q4 remains required."
  };
  result.reporter_contract = { observer_version: "g03-observer-v4", observer_schema: 5, longflow_version: "g03-longflow-v4", longflow_schema: 3, coverage_contract_sha256: "5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810", whole_primary_scope_quality_required: true };
  if (mode === "qualification") {
    result.revision = "R4";
    result.purpose = "One80s heavy-native-DOWNLOAD/ChromeGoogle/GoIdle capture qualification using prospectively selected stress-tested sensor and v4 reporters; no calibration";
    result.groups = result.groups.map(g => ({ ...g, source_workload_id: g.source_workload_id.replace(/^q-r3-/, "q-r4-") }));
  } else {
    result.revision = { id: "R4", physical_acquisition: "All71 train/validation groups newly captured after successful Q4; all stopped prior cohorts remain development", changed: "355 fresh CSPRNG nonces; selected capture sensor; v4 whole-primary QC", unchanged: "All workload source seeds, source partitions, groups/batches and25 sealed test rows" };
    result.seeds.train_validation_nonces = "R4 CSPRNG355 unique values, disjoint from supplied public prior plans; pinned before acquisition";
    validate(result);
  }
  return result;
}

if (require.main === module) {
  const [mode, sourcePath, masterPath, sensorPath, output, ...previous] = process.argv.slice(2);
  if (!output || mode !== "qualification") throw Error("usage: node make-r4.cjs qualification SOURCE R2_MASTER ROOT_SENSOR_REVIEW NEW_OUTPUT [PREVIOUS_PUBLIC_PLANS...]; B1 requires a successful independent Q4 review via derive");
  const sourceRaw = fs.readFileSync(sourcePath), masterRaw = fs.readFileSync(masterPath), sensorRaw = fs.readFileSync(sensorPath);
  const prior = previous.map(filename => ({ filename, raw: fs.readFileSync(filename) }));
  const result = derive(mode, JSON.parse(sourceRaw), JSON.parse(masterRaw), JSON.parse(sensorRaw), prior.map(p => JSON.parse(p.raw)));
  result.lineage = { created_utc: new Date().toISOString(), source_assignments_sha256: sha(sourceRaw), parent_collector_sha256: sha(masterRaw), sensor_review_sha256: sha(sensorRaw), generator_sha256: sha(fs.readFileSync(__filename)), generator_R3_dependency_sha256: sha(fs.readFileSync(require.resolve("./make-r3.cjs"))), prior_public_plans: prior.map(p => ({ path: p.filename, sha256: sha(p.raw) })), private_test_values_read: false };
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o644 });
  console.log(JSON.stringify({ output, mode, sha256: sha(fs.readFileSync(output)), groups: result.groups.length, private_test_values_read: false }));
}
module.exports = { derive };

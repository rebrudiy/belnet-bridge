"use strict";
// Releases a completed, source-verified cohort to the NEW uncertainty analysis.
// Keeps the strict audit intact. Does not score, fit, or certify a DPI policy.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { guardFreeze } = require("./review-r4.cjs");
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const CONTRACT = "r4-worst-case-benign-fp-v1";

function preflight(frozen, strict, freezeSHA, completion, restoration) {
  guardFreeze(frozen);
  if (frozen.stage !== "B1" || strict.schema !== "g03-root-acquisition-review/v4" || strict.stage !== "B1" || strict.freeze_sha256 !== freezeSHA || strict.expected_groups !== 71 || strict.reviewed_groups !== 71 || strict.groups?.length !== 71 || strict.missing_groups?.length !== 0 || strict.private_test_values_read !== false)
    throw Error("complete_independent_71_group_B1_audit_required");
  if (completion.attempted !== 71 || completion.total !== 71 || completion.stopped_after_batch !== false || completion.groups?.length !== 71 || completion.groups.some(g => g.errors?.length !== 0) || !Number.isFinite(Date.parse(completion.finished_utc)) || restoration.all_restored !== true)
    throw Error("terminal_completed_cohort_and_restoration_required");
  if (strict.errors?.length !== 0 || strict.pins?.length !== Object.keys(frozen.files_sha256).length || strict.pins.some(p => p.matches !== true) || strict.pins.some(p => !Object.hasOwn(frozen.files_sha256, p.path)) || new Set(strict.pins.map(p => p.path)).size !== strict.pins.length)
    throw Error("all_independent_source_pins_must_match");
  for (const rows of [strict.groups.map(g => g.group_id), completion.groups.map(g => g.id)]) {
    if (new Set(rows).size !== 71 || rows.some(id => !frozen.groups.some(g => g.group_id === id))) throw Error("exact_frozen_cohort_required");
  }
  const blocking = strict.groups.flatMap(g => (g.errors || []).filter(e => e !== "reporter_coverage_unknown").map(error => ({ group_id: g.group_id, error })));
  if (blocking.length) throw Error("raw_or_contract_failures_cannot_be_waived:" + JSON.stringify(blocking));
}

function qualifyGroups(strictGroups, summaries) {
  const groups = [];
  for (const g of strictGroups) {
    const s = summaries[g.group_id];
    if (!s || !s.primary_flow_ids?.length || new Set(s.primary_flow_ids).size !== s.primary_flow_ids.length || s.inventory_fields_valid !== true || s.longflow_inventory_censored || s.longflow_omitted_flow_records)
      throw Error("bounded_valid_primary_inventory_required:" + g.group_id);
    if (g.primary_flows !== s.primary_flow_ids.length) throw Error("strict_inventory_count_mismatch:" + g.group_id);
    if (g.errors.length === 0 && (s.observer_complete !== true || s.longflow_complete !== true)) throw Error("strict_coverage_verdict_changed:" + g.group_id);
    const reasons = s.global_reasons || [];
    if (reasons.some(r => !r.startsWith("primary_flow_fault: "))) throw Error("unmapped_global_fault_requires_separate_review:" + g.group_id);
    groups.push({ group_id: g.group_id, strict_acquisition_qualified: g.acquisition_qualified, semantic_coverage_complete: s.observer_complete === true && s.longflow_complete === true, semantic_unknown: s.observer_complete !== true || s.longflow_complete !== true, primary_flow_inventory: s.primary_flow_ids, original_coverage_reasons: reasons, raw_acquisition_qualified: true });
  }
  return groups;
}

function validateIndex(index, frozen) {
  if (index.schema !== 4 || index.stage !== "B1" || index.reports?.length !== 71 || new Set(index.reports.map(r => r.group_id)).size !== 71 || index.coverage_errors?.length)
    throw Error("exact_complete_typed_B1_index_required");
  for (const ref of index.reports) {
    const g = frozen.groups.find(g => g.group_id === ref.group_id);
    if (!g || ref.split !== g.split || !["train", "validation"].includes(ref.split) || ref.path !== g.group_id + "/windows.json" || ref.longflow_path !== g.group_id + "/longflow.json" || ref.coverage_errors?.length)
      throw Error("index_assignment_or_raw_coverage_mismatch");
  }
}

function verifyPreparation(frozen, read) {
  if (path.resolve(frozen.prepared.path) === path.resolve(frozen.test_seeds_commitment.path)) throw Error("prepared_descriptor_test_reference");
  const raw = read(frozen.prepared.path);
  if (hash(raw) !== frozen.prepared.sha256) throw Error("prepared_descriptor_changed");
  const prep = JSON.parse(raw), base = path.resolve(prep.directory);
  const assets = Object.entries(prep.assets_sha256 || {});
  if (!assets.length || !prep.adapter || !prep.sing_box) throw Error("prepared_assets_and_binaries_required");
  for (const [name, expected] of assets) {
    const file = path.resolve(base, name);
    if (path.isAbsolute(name) || !file.startsWith(base + path.sep) || file === path.resolve(frozen.test_seeds_commitment.path)) throw Error("prepared_asset_path_invalid_or_test_reference");
    if (hash(read(file)) !== expected) throw Error("prepared_asset_changed:" + name);
  }
  const binaries = [prep.adapter, prep.sing_box, ...(prep.libraries || [])];
  for (const binary of binaries) {
    if (path.resolve(binary.path) === path.resolve(frozen.test_seeds_commitment.path)) throw Error("prepared_binary_test_reference");
    if (hash(read(binary.path)) !== binary.sha256) throw Error("prepared_binary_changed:" + binary.path);
  }
  return { path: path.resolve(frozen.prepared.path), sha256: hash(raw), assets_checked: assets.length, binaries_checked: binaries.length };
}

function audit(directory, freezePath, strictPath) {
  let forbiddenTestPath = null;
  const inputs = {}, read = file => { if (forbiddenTestPath && path.resolve(file) === forbiddenTestPath) throw Error("private_test_reference_rejected_before_read"); const raw = fs.readFileSync(file); inputs[path.resolve(file)] = hash(raw); return raw; };
  const frozenRaw = read(freezePath), frozen = JSON.parse(frozenRaw); guardFreeze(frozen);
  if (frozen.stage !== "B1") throw Error("development_B1_only_before_further_reads");
  if (typeof frozen.test_seeds_commitment?.path !== "string") throw Error("original_test_commitment_path_required_without_reading_values");
  forbiddenTestPath = path.resolve(frozen.test_seeds_commitment.path);
  const strictRaw = read(strictPath), strict = JSON.parse(strictRaw);
  // The completion files exist only after the collector's finally/restoration.
  const completion = JSON.parse(read(path.join(directory, "completion.json"))), restoration = JSON.parse(read(path.join(directory, "restoration.json")));
  preflight(frozen, strict, hash(frozenRaw), completion, restoration);
  const strictSource = read(require.resolve("./review-r4.cjs"));
  if (hash(strictSource) !== strict.auditor_sha256) throw Error("strict_auditor_source_changed_since_audit");
  if (!Array.isArray(strict.inputs) || !strict.inputs.length) throw Error("strict_input_hashes_required");
  for (const input of strict.inputs) {
    if (hash(read(input.path)) !== input.sha256) throw Error("strict_input_changed:" + input.path);
  }
  const prepared = verifyPreparation(frozen, read);
  const indexPath = path.join(directory, "observer-index.json"), indexRaw = read(indexPath);
  validateIndex(JSON.parse(indexRaw), frozen);
  const summaries = {};
  for (const g of frozen.groups) {
    const dir = path.join(directory, g.group_id), observerPath = path.join(dir, "windows.json"), longflowPath = path.join(dir, "longflow.json");
    for (const file of [observerPath, longflowPath, path.join(dir, "outer.pcap"), path.join(dir, "result.json")]) {
      if (!strict.inputs.some(i => path.resolve(i.path) === path.resolve(file))) throw Error("required_strict_input_missing:" + file);
    }
    const o = JSON.parse(read(observerPath)), l = JSON.parse(read(longflowPath));
    summaries[g.group_id] = { primary_flow_ids: o.flows.filter(f => f.primary_scope).map(f => f.flow_id), inventory_fields_valid: o.flows.every(f => typeof f.primary_scope === "boolean" && Number.isSafeInteger(f.raw_tcp_payload_bytes_including_retransmits) && f.raw_tcp_payload_bytes_including_retransmits >= 0), global_reasons: o.global_coverage_reasons, observer_complete: o.coverage_complete, longflow_complete: l.source_observer_coverage_complete, longflow_inventory_censored: l.collector_flow_censored, longflow_omitted_flow_records: l.collector_omitted_flow_records };
  }
  const groups = qualifyGroups(strict.groups, summaries);
  return { schema: "g03-root-conservative-analysis-release/v1", analysis_contract: CONTRACT, checked_utc: new Date().toISOString(), stage: "B1", analysis_input_allowed: true, terminal_completed: true, completion_finished_utc: completion.finished_utc, raw_acquisition_complete: true, semantic_coverage_complete: groups.every(g => !g.semantic_unknown), strict_acquisition_qualified: strict.acquisition_qualified, prepared, frozen_collector_sha256: hash(frozenRaw), collector_freeze: { path: path.resolve(freezePath), sha256: hash(frozenRaw) }, observer_index: { path: path.resolve(indexPath), sha256: hash(indexRaw) }, strict_audit: { path: path.resolve(strictPath), sha256: hash(strictRaw), auditor_sha256: strict.auditor_sha256 }, groups, expected_groups: 71, observed_groups: groups.length, semantic_unknown_groups: groups.filter(g => g.semantic_unknown).map(g => g.group_id), private_test_values_read: false, classifier_fitting_performed: false, certified_policy_issued: false, input_sha256: inputs, auditor_sha256: hash(fs.readFileSync(__filename)), limits: ["Input release only to the new worst-case analysis; strict verdicts unchanged", "All unknown benign groups and affected flows must consume the joint5% FP budget", "No certified policy if uncertainty floor exceeds budget or inventory cannot be bounded", "No real ISP, live enforcement or native application success claim"] };
}
if (require.main === module) {
  const [directory, freeze, strict, output] = process.argv.slice(2); if (!output) throw Error("usage: node review-analysis-r4.cjs RUN FREEZE STRICT_AUDIT NEW_OUTPUT");
  const result = audit(directory, freeze, strict); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ analysis_input_allowed: result.analysis_input_allowed, raw_acquisition_complete: result.raw_acquisition_complete, groups: result.observed_groups, semantic_unknown: result.semantic_unknown_groups, strict_verdict_unchanged: result.strict_acquisition_qualified }));
}
module.exports = { audit, preflight, qualifyGroups, validateIndex, verifyPreparation, CONTRACT };

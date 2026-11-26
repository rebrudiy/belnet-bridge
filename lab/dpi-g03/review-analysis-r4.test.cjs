"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { preflight, qualifyGroups, validateIndex, verifyPreparation } = require("./review-analysis-r4.cjs");
const crypto = require("node:crypto"), path = require("node:path");
function fixture() {
  const groups = Array.from({ length: 71 }, (_, i) => ({ group_id: "b-train-" + i, split: "train", scope: "primary" }));
  const frozen = { schema: "belnet-g03-collector/v4", stage: "B1", groups, files_sha256: { "source.go": "a".repeat(64) } };
  const strict = { schema: "g03-root-acquisition-review/v4", stage: "B1", freeze_sha256: "f".repeat(64), expected_groups: 71, reviewed_groups: 71, groups: groups.map(g => ({ group_id: g.group_id, errors: [], primary_flows: 1, acquisition_qualified: true })), missing_groups: [], errors: [], pins: [{ path: "source.go", matches: true }], private_test_values_read: false };
  const completion = { attempted: 71, total: 71, stopped_after_batch: false, finished_utc: "2026-11-19T20:00:00Z", groups: groups.map(g => ({ id: g.group_id, errors: [] })) };
  const summaries = Object.fromEntries(groups.map(g => [g.group_id, { primary_flow_ids: ["tcp"], inventory_fields_valid: true, observer_complete: true, longflow_complete: true, longflow_inventory_censored: false, longflow_omitted_flow_records: 0, global_reasons: [] }]));
  return { frozen, strict, completion, restoration: { all_restored: true }, summaries };
}
test("complete raw cohort can expose semantic UNKNOWN without rewriting strict verdict", () => {
  const f = fixture(); f.strict.groups[0].errors = ["reporter_coverage_unknown"]; f.strict.groups[0].acquisition_qualified = false;
  Object.assign(f.summaries["b-train-0"], { observer_complete: false, longflow_complete: false, global_reasons: ["primary_flow_fault: partial_final_tls_record"] });
  assert.doesNotThrow(() => preflight(f.frozen, f.strict, "f".repeat(64), f.completion, f.restoration));
  const groups = qualifyGroups(f.strict.groups, f.summaries); assert.equal(groups.length, 71); assert.equal(groups.filter(g => g.semantic_unknown).length, 1); assert.equal(groups[0].strict_acquisition_qualified, false);
});
test("partial cohort, test references and incomplete restoration cannot release", () => {
  for (const change of [f => { f.strict.reviewed_groups = 70; }, f => { f.frozen.groups[0].split = "test"; }, f => { f.restoration.all_restored = false; }, f => { f.completion.stopped_after_batch = true; }]) {
    const f = fixture(); change(f); assert.throws(() => preflight(f.frozen, f.strict, "f".repeat(64), f.completion, f.restoration));
  }
});
test("capture, metadata and source failures cannot hide under semantic uncertainty", () => {
  for (const reason of ["raw_capture_accounting_or_lifecycle", "reporter_metadata_binding", "VM_horizon_quiesce_drain", "primary_handshake_inventory_missing"]) {
    const f = fixture(); f.strict.groups[0].errors = ["reporter_coverage_unknown", reason];
    assert.throws(() => preflight(f.frozen, f.strict, "f".repeat(64), f.completion, f.restoration), /cannot_be_waived/);
  }
  const f = fixture(); f.strict.pins[0].matches = false; assert.throws(() => preflight(f.frozen, f.strict, "f".repeat(64), f.completion, f.restoration), /pins_must_match/);
});
test("missing/censored inventory and unaccounted global faults remain blocking", () => {
  for (const change of [s => { s.primary_flow_ids = []; }, s => { s.inventory_fields_valid = false; }, s => { s.longflow_inventory_censored = true; }, s => { s.longflow_omitted_flow_records = 1; }, s => { s.global_reasons = ["flow_limit_reached"]; }]) {
    const f = fixture(); change(f.summaries["b-train-0"]); assert.throws(() => qualifyGroups(f.strict.groups, f.summaries));
  }
});
test("index cannot replace full primary cohort with test, missing or raw-fault references", () => {
  const f = fixture(), index = { schema: 4, stage: "B1", reports: f.frozen.groups.map(g => ({ group_id: g.group_id, split: g.split, path: g.group_id + "/windows.json", longflow_path: g.group_id + "/longflow.json", coverage_errors: [] })) };
  assert.doesNotThrow(() => validateIndex(index, f.frozen));
  for (const change of [x => { x.reports.pop(); }, x => { x.reports[0].split = "test"; }, x => { x.reports[0].path = "../test/windows.json"; }, x => { x.reports[0].coverage_errors = ["kernel_drops"]; }]) {
    const bad = structuredClone(index); change(bad); assert.throws(() => validateIndex(bad, f.frozen));
  }
});
test("prepared descriptor cannot hide changed binaries/assets or cause a private test read", () => {
  const sha = b => crypto.createHash("sha256").update(b).digest("hex"), body = Buffer.from("immutable fixture");
  const prep = { directory: "/fixture", assets_sha256: { "asset": sha(body) }, adapter: { path: "/adapter", sha256: sha(body) }, sing_box: { path: "/core", sha256: sha(body) } };
  const make = () => { const raw = Buffer.from(JSON.stringify(prep)); return { frozen: { prepared: { path: "/prep.json", sha256: sha(raw) }, test_seeds_commitment: { path: "/private-test" } }, raw }; };
  let f = make(); const read = file => file === "/prep.json" ? f.raw : body;
  assert.equal(verifyPreparation(f.frozen, read).binaries_checked, 2);
  assert.throws(() => verifyPreparation({ ...f.frozen, prepared: { path: "/private-test" } }, () => { throw Error("private test was opened"); }), /prepared_descriptor_test_reference/);
  assert.throws(() => verifyPreparation(f.frozen, file => path.resolve(file) === "/adapter" ? Buffer.from("changed") : read(file)), /binary_changed/);
  prep.assets_sha256 = { "../private-test": sha(body) }; f = make();
  assert.throws(() => verifyPreparation(f.frozen, file => { if (file === "/private-test") throw Error("private test file was opened"); return read(file); }), /path_invalid_or_test_reference/);
});

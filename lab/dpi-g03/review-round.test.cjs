"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { guardRound, qualifyRoundResults } = require("./review-round.cjs");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
function fixture() {
  let nonce = 0;
  const groups = ["rpc", "download", "upload"].map((family, i) => ({ group_id: "b-" + (i === 1 ? "validation" : "train") + "-native-cycle01-" + family, split: i === 1 ? "validation" : "train", scope: "primary", class: "belnet", stratum: "native", experiment_role: "candidate-development", adaptive_round: 1, fresh_native_identity_required: true, family, seed_int: i + 1, nonce: (++nonce).toString(16).padStart(64, "0"), initial_nonce: (++nonce).toString(16).padStart(64, "0"), warmup_nonces: Array.from({ length: 3 }, () => (++nonce).toString(16).padStart(64, "0")) }));
  return { schema: "belnet-g03-collector/v4", stage: "B1", adaptive_round: 1, experiment_role: "candidate-development", groups, batches: groups.map(g => [g.group_id]), capture_mode: "buffered", capture_buffer_kib: 16384, measured_seconds: 80, capture_seconds: 82, stats_drain_budget_ms: 2500, stats_stable_ms: 100, quiesce_drain_micros: 500000, files_sha256: { "source.cjs": "a".repeat(64) } };
}
test("adaptive gate accepts explicit three-family round and rejects Q/test/full-B1 masquerading as a round", () => {
  assert.doesNotThrow(() => guardRound(fixture()));
  for (const mutate of [f => { f.adaptive_round = 0; }, f => { f.stage = "Q"; }, f => { f.groups[0].split = "test"; }, f => { delete f.groups[0].experiment_role; }, f => { f.groups[0].fresh_native_identity_required = false; }]) { const f = fixture(); mutate(f); assert.throws(() => guardRound(f)); }
});
test("family omission, nonce reuse and concurrent native batches are rejected before I/O", () => {
  for (const mutate of [f => { f.groups[0].family = "download"; }, f => { f.groups[1].nonce = f.groups[0].nonce; }, f => { f.batches = [[f.groups[0].group_id, f.groups[1].group_id], [f.groups[2].group_id]]; }, f => { f.groups[0].adaptive_round = 2; }]) { const f = fixture(); mutate(f); assert.throws(() => guardRound(f)); }
});
test("capture changes cannot silently enter a counted transport round", () => {
  for (const mutate of [f => { f.capture_buffer_kib = 1024; }, f => { f.capture_mode = "immediate"; }, f => { f.capture_seconds = 4; }, f => { f.files_sha256 = {}; }]) { const f = fixture(); mutate(f); assert.throws(() => guardRound(f)); }
});
test("native round join rejects non-round/test scope before opening service logs", t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "belnet-native-round-guard-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { audit } = require("./review-native-round.cjs"), f = fixture(), filename = path.join(directory, "freeze.json");
  f.stage = "Q"; fs.writeFileSync(filename, JSON.stringify(f));
  assert.throws(() => audit(directory, filename), /explicit_adaptive_development_round_required/);
  f.stage = "B1"; f.groups[0].split = "test"; fs.writeFileSync(filename, JSON.stringify(f));
  assert.throws(() => audit(directory, filename), /native_primary_train_validation_only/);
});
test("round raw release preserves a semantic UNKNOWN without waiving raw, metadata or incomplete collection failures", () => {
  const s = { terminal: true, missing: [], errors: [], groups: [{ group_id: "g", errors: ["reporter_coverage_unknown"] }] };
  assert.equal(qualifyRoundResults(s).rawQualified, true);
  for (const mutate of [x => { x.groups[0].errors.push("raw_capture_accounting_or_lifecycle"); }, x => { x.groups[0].errors.push("reporter_metadata_binding"); }, x => { x.missing = ["missing"]; }, x => { x.terminal = false; }, x => { x.errors = ["source_pin_changed"]; }]) {
    const bad = structuredClone(s); mutate(bad); assert.equal(qualifyRoundResults(bad).rawQualified, false);
  }
});

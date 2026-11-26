"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { makeAssignments } = require("./make-assignments.cjs"), { derive } = require("./make-r4.cjs");
const master = { stage: "B1", test_seeds_commitment: { sha256: "a".repeat(64) } };
const sensor = { schema: "g03-root-capture-stress-review/v1", qualified: true, errors: [], selected: "buffered16", capture_mode: "buffered", buffer_kib: 16384, private_test_values_read: false };
const fresh = () => { let n = 0; return () => (++n).toString(16).padStart(64, "0"); };
const q = { schema: "g03-root-acquisition-review/v4", stage: "Q", acquisition_qualified: true, expected_groups: 3, reviewed_groups: 3, groups: Array.from({ length: 3 }, () => ({ acquisition_qualified: true })) };
test("Q4 binds selected capture and v4 coverage without adding test scope", () => {
  const p = derive("qualification", makeAssignments(), master, sensor, [], fresh());
  assert.equal(p.revision, "R4"); assert.equal(p.groups.length, 3);
  assert.deepEqual(p.groups.map(g => g.group_id), ["q-native-download", "q-chrome-google", "q-go-idle"]);
  assert.ok(p.groups.every(g => g.scope === "diagnostic" && g.split === "development" && g.source_workload_id.startsWith("q-r4-")));
  assert.equal(p.capture_shutdown.immediate_mode, false); assert.equal(p.capture_shutdown.buffer_kib, 16384);
  assert.equal(p.reporter_contract.observer_version, "g03-observer-v4"); assert.equal(p.test_vault_required, false); assert.equal(p.detector_fitting_allowed, false);
});
test("failed or inconsistent sensor evidence cannot produce a plan", () => {
  for (const bad of [null, { ...sensor, qualified: false }, { ...sensor, errors: ["drop"] }, { ...sensor, buffer_kib: 65536 }, { ...sensor, private_test_values_read: true }])
    assert.throws(() => derive("qualification", makeAssignments(), master, bad, [], fresh()), /review_required|mode_mismatch/);
});
test("B1 requires full Q4 review; preserves sealed rows and refreshes exactly355 nonces", () => {
  const plan = makeAssignments(); assert.throws(() => derive("b1", plan, master, sensor, [], fresh()), /Q4_review/);
  const p = derive("b1", plan, master, sensor, [], fresh(), q), nonces = [];
  for (let i = 0; i < plan.groups.length; i++) {
    const old = plan.groups[i], next = p.groups[i];
    if (old.split === "test") assert.deepEqual(next, old);
    else { const strip = g => Object.fromEntries(Object.entries(g).filter(([k]) => !["nonce", "initial_nonce", "warmup_nonces"].includes(k))); assert.deepEqual(strip(next), strip(old)); nonces.push(next.nonce, next.initial_nonce, ...next.warmup_nonces); }
  }
  assert.equal(nonces.length, 355); assert.equal(new Set(nonces).size, 355); assert.deepEqual(p.stages, plan.stages);
  assert.equal(p.seeds.test_seed_commitment_sha256, master.test_seeds_commitment.sha256);
});
test("prior public nonces cannot be reused", () => {
  const plan = makeAssignments(), prior = { groups: [{ split: "development", nonce: "b".repeat(64) }] };
  assert.throws(() => derive("qualification", plan, master, sensor, [prior], () => "b".repeat(64)), /collision/);
});
test("test initial and warmup nonces remain sealed in source and prior public plans", () => {
  for (const mutate of [g => { g.initial_nonce = "d".repeat(64); }, g => { g.warmup_nonces[1] = "e".repeat(64); }, g => { g.seed_int = 17; }]) {
    const plan = makeAssignments(); mutate(plan.groups.find(g => g.split === "test"));
    assert.throws(() => derive("qualification", plan, master, sensor, [], fresh()), /all_test_seed_and_nonce_fields_must_remain_sealed/);
    assert.throws(() => derive("b1", makeAssignments(), master, sensor, [plan], fresh(), q), /all_test_seed_and_nonce_fields_must_remain_sealed/);
  }
});

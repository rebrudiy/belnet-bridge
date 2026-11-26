"use strict";
const fs = require("node:fs");
const crypto = require("node:crypto");
const { validate } = require("./make-assignments.cjs");
const sha = (raw) => crypto.createHash("sha256").update(raw).digest("hex");

function revise(plan, parentFreeze, lineage, fresh = () => crypto.randomBytes(32).toString("hex")) {
  validate(plan);
  if (parentFreeze.stage !== "B1" || !/^[a-f0-9]{64}$/.test(parentFreeze.test_seeds_commitment?.sha256 || ""))
    throw new Error("existing_B1_test_commitment_required");
  const revised = structuredClone(plan);
  const used = new Set(plan.groups.filter(g => g.split !== "test").flatMap(g => [g.nonce, g.initial_nonce, ...g.warmup_nonces]));
  function nonce() {
    const value = fresh();
    if (!/^[a-f0-9]{64}$/.test(value) || used.has(value)) throw new Error("fresh_nonce_invalid_or_collision");
    used.add(value);
    return value;
  }
  for (const group of revised.groups) {
    if (group.split === "test") continue;
    group.nonce = nonce();
    group.initial_nonce = nonce();
    group.warmup_nonces = [nonce(), nonce(), nonce()];
  }
  revised.revision = {
    id: "R2",
    ...lineage,
    physical_acquisition: "All71 train/validation groups are new runs; old15 are collector development only",
    unchanged: "Group IDs, source plans/seeds, splits, workloads, batches and all25 sealed-test rows",
    changed: "355 fresh CSPRNG nonces for71 train/validation groups; no test values read",
  };
  revised.seeds.train_validation_nonces = "R2 CSPRNG,355 distinct values, disjoint from all original train/validation nonces; pinned in this file before collection";
  revised.seeds.test_seed_commitment_sha256 = parentFreeze.test_seeds_commitment.sha256;
  validate(revised);
  return revised;
}

if (require.main === module) {
  const [parent, freezePath, output] = process.argv.slice(2);
  if (!parent || !freezePath || !output) throw new Error("usage: node make-r2-assignments.cjs ORIGINAL_ASSIGNMENTS ORIGINAL_B1_FREEZE NEW_OUTPUT");
  const originalRaw = fs.readFileSync(parent), freezeRaw = fs.readFileSync(freezePath);
  const revised = revise(JSON.parse(originalRaw), JSON.parse(freezeRaw), {
    created_utc: new Date().toISOString(), parent_assignments_sha256: sha(originalRaw),
    parent_collector_freeze_sha256: sha(freezeRaw), generator_sha256: sha(fs.readFileSync(__filename)),
  });
  fs.writeFileSync(output, JSON.stringify(revised, null, 2) + "\n", { flag: "wx", mode: 0o644 });
  console.log(JSON.stringify({ output, sha256: sha(fs.readFileSync(output)), groups: revised.groups.length, fresh_nonces: 355, sealed_rows_unchanged: true }));
}
module.exports = { revise };

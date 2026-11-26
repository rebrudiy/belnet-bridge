"use strict";
// Separate CLI preserves the exact Q4 generator bytes after its plan is frozen.
const fs = require("node:fs"), crypto = require("node:crypto");
const { derive } = require("./make-r4.cjs");
const { guardFreeze } = require("./review-r4.cjs");
const hash = raw => crypto.createHash("sha256").update(raw).digest("hex");
function main(argv) {
  const [sourcePath, masterPath, sensorPath, qFreezePath, qAuditPath, output, ...previous] = argv;
  if (!output) throw Error("usage: node make-b1-r4.cjs SOURCE R2_MASTER SENSOR_REVIEW Q4_FREEZE Q4_REVIEW NEW_OUTPUT [PREVIOUS_PUBLIC_PLANS...]");
  const sourceRaw = fs.readFileSync(sourcePath), masterRaw = fs.readFileSync(masterPath), sensorRaw = fs.readFileSync(sensorPath), qFrozenRaw = fs.readFileSync(qFreezePath), qAuditRaw = fs.readFileSync(qAuditPath);
  const qFrozen = JSON.parse(qFrozenRaw), qAudit = JSON.parse(qAuditRaw); guardFreeze(qFrozen);
  if (qFrozen.stage !== "Q" || qAudit.stage !== "Q" || qAudit.freeze_sha256 !== hash(qFrozenRaw) || qAudit.private_test_values_read !== false || qAudit.errors?.length !== 0 || qAudit.missing_groups?.length !== 0 || qAudit.groups?.map(g => g.group_id).sort().join(",") !== qFrozen.groups.map(g => g.group_id).sort().join(",")) throw Error("Q4_review_must_bind_exact_complete_frozen_cohort");
  const prior = previous.map(filename => ({ filename, raw: fs.readFileSync(filename) }));
  const result = derive("b1", JSON.parse(sourceRaw), JSON.parse(masterRaw), JSON.parse(sensorRaw), [...prior.map(p => JSON.parse(p.raw)), { groups: qFrozen.groups }], undefined, qAudit);
  result.lineage = { created_utc: new Date().toISOString(), source_assignments_sha256: hash(sourceRaw), parent_collector_sha256: hash(masterRaw), sensor_review_sha256: hash(sensorRaw), qualification_freeze_sha256: hash(qFrozenRaw), qualification_review_sha256: hash(qAuditRaw), generator_sha256: hash(fs.readFileSync(__filename)), dependencies_sha256: Object.fromEntries(["./make-r4.cjs", "./make-r3.cjs", "./make-assignments.cjs", "./review-r4.cjs"].map(name => [name, hash(fs.readFileSync(require.resolve(name)))])), prior_public_plans: prior.map(p => ({ path: p.filename, sha256: hash(p.raw) })), private_test_values_read: false };
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o644 });
  return { output, groups: result.groups.length, acquisition_groups: result.stages.B1.order.length, sha256: hash(fs.readFileSync(output)), private_test_values_read: false };
}
if (require.main === module) console.log(JSON.stringify(main(process.argv.slice(2))));
module.exports = { main };

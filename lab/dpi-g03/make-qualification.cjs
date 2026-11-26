"use strict";
const fs = require("node:fs"), crypto = require("node:crypto");
const sha = raw => crypto.createHash("sha256").update(raw).digest("hex");
function make(plan) {
  const selections = [
    ["b-train-native-rpc-1", "q-native-rpc"],
    ["b-train-public-google", "q-chrome-google"],
    ["b-train-long-idle-2", "q-go-idle"],
  ];
  const used = new Set(plan.groups.filter(g => g.split !== "test").flatMap(g => [g.nonce, g.initial_nonce, ...g.warmup_nonces]));
  function nonce() {
    const value = crypto.randomBytes(32).toString("hex");
    if (used.has(value)) throw new Error("qualification_nonce_collision");
    used.add(value); return value;
  }
  const groups = selections.map(([sourceID, id]) => {
    const source = plan.groups.find(g => g.group_id === sourceID);
    if (!source || source.split !== "train") throw new Error("qualification_requires_declared_train_source");
    const group = structuredClone(source);
    Object.assign(group, { group_id: id, source_workload_id: "q-" + source.source_workload_id, split: "development", scope: "diagnostic", qualification_source_group_id: sourceID, nonce: nonce(), initial_nonce: nonce(), warmup_nonces: [nonce(), nonce(), nonce()] });
    return group;
  });
  const order = groups.map(g => g.group_id);
  return {
    schema: "belnet-g03-qualification/v1", stage: "Q", created_utc: new Date().toISOString(),
    purpose: "One80s collector qualification batch, excluded from calibration and B1/B2 denominators",
    test_vault_required: false, detector_fitting_allowed: false,
    primary_seconds: 80, capture_seconds: 82, prefix_grace_seconds: 2,
    window_offsets_seconds: plan.window_offsets_seconds, window_seconds: 2,
    resource_limits: plan.resource_limits,
    stages: { Q: { splits: ["development"], count: 3, order, batches: [order] } }, groups,
  };
}
if (require.main === module) {
  const [source, output] = process.argv.slice(2);
  if (!source || !output) throw new Error("usage: node make-qualification.cjs R2_ASSIGNMENTS NEW_Q_OUTPUT");
  const raw = fs.readFileSync(source), plan = make(JSON.parse(raw));
  plan.source_assignments_sha256 = sha(raw);
  plan.generator_sha256 = sha(fs.readFileSync(__filename));
  fs.writeFileSync(output, JSON.stringify(plan, null, 2) + "\n", { flag: "wx", mode: 0o644 });
  console.log(JSON.stringify({ output, sha256: sha(fs.readFileSync(output)), groups: plan.groups.map(g => ({ id: g.group_id, split: g.split, scope: g.scope })), test_vault_required: false }));
}
module.exports = { make };

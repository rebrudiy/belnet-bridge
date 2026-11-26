"use strict";
const fs = require("fs"),
  path = require("path");
const { ROOT, hash, save, args } = require("./common.cjs");
function tooling() {
  const observer = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, "out/dpi-g03/tooling-observer/TOOLING.json"),
      ),
    ),
    defender = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, "out/dpi-g03/tooling-defender/TOOLING.json"),
      ),
    );
  const result = {
    observer: observer.binary.observer,
    defender: defender.binary.defender,
    engine: defender.binary.classical,
    definitions_sha256: defender.definitions_sha256,
  };
  for (const b of [result.observer, result.defender, result.engine]) {
    b.path = path.join(ROOT, b.versioned_path);
    if (hash(b.path) !== b.sha256)
      throw Error("Versioned tooling binary changed");
  }
  return result;
}
function projection(master, out) {
  const f = JSON.parse(fs.readFileSync(master)),
    t = tooling();
  if (f.stage !== "B1") throw Error("Only B1 projection currently authorized");
  if (fs.existsSync(out)) throw Error("Projection exists");
  const p = {
    schema: 3,
    stage: "B1",
    stage_a_viability: "proceed",
    frozen_at: new Date().toISOString(),
    collector_freeze_sha256: hash(master),
    measured_seconds: 80,
    capture_seconds: 82,
    prefix_grace_seconds: 2,
    window_offsets_seconds: f.window_offsets_seconds,
    window_seconds: 2,
    cooldown_seconds: 30,
    capture_cap_bytes: f.pcap_cap_bytes,
    group_fpr_budget: 0.05,
    direct_flow_fpr_budget: 0.05,
    definitions_sha256: t.definitions_sha256,
    score_engine_sha256: t.engine.sha256,
    observer_sha256: t.observer.sha256,
    observer_version: "g03-observer-v1",
    groups: f.groups.map((g) =>
      Object.fromEntries(
        [
          "group_id",
          "source_workload_id",
          "scope",
          "transport",
          "client_stack",
          "split",
          "class",
          "profile",
        ].map((k) => [k, g[k]]),
      ),
    ),
  };
  save(out, p);
  return p;
}
if (require.main === module) {
  const a = args(process.argv.slice(2));
  try {
    projection(a.master, a.output);
    console.log(
      JSON.stringify({ projection: a.output, sha256: hash(a.output) }),
    );
  } catch (e) {
    console.error(e.stack);
    process.exitCode = 1;
  }
}
module.exports = { tooling, projection };

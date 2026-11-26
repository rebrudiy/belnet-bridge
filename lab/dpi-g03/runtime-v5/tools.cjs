"use strict";
const fs = require("fs"),
  path = require("path");
const { ROOT, hash, save, args } = require("./common.cjs");
function tooling({ observationOnly = false } = {}) {
  const observer = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, "lab/dpi-g03/observer-v4/tooling/TOOLING.json"),
      ),
    ),
    long = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, "lab/dpi-g03/longflow-v4/tooling/TOOLING.json"),
      ),
    ),
    old = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, "out/dpi-g03/tooling-defender/TOOLING.json"),
      ),
    );
  const result = {
    observer: observer.binary.observer,
    longflow: long.binary.longflow,
    engine: old.binary.classical,
    window_definitions_sha256: old.definitions_sha256,
    longflow_definitions_sha256: long.feature_definitions_sha256,
    ordering_semantics_sha256: observer.ordering_semantics_sha256,
    coverage_semantics_sha256: observer.coverage_semantics_sha256,
  };
  if (long.coverage_semantics_sha256 !== result.coverage_semantics_sha256)
    throw Error("Coverage contracts disagree");
  if (long.ordering_semantics_sha256 !== result.ordering_semantics_sha256)
    throw Error("Observation ordering contracts disagree");
  if (!observationOnly) {
    const model = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, "lab/dpi-g03/ensemble-v2/tooling/TOOLING.json"),
      ),
    );
    result.defender = model.binary.ensemble;
    result.definitions_sha256 = model.definitions_sha256;
    if (
      model.coverage_semantics_sha256 !== result.coverage_semantics_sha256 ||
      model.ordering_semantics_sha256 !== result.ordering_semantics_sha256 ||
      model.longflow_definitions_sha256 !== result.longflow_definitions_sha256
    )
      throw Error("Ensemble observation definitions disagree");
  }
  for (const b of [
    result.observer,
    result.longflow,
    result.engine,
    ...(result.defender ? [result.defender] : []),
  ]) {
    b.path = path.isAbsolute(b.versioned_path)
      ? b.versioned_path
      : path.join(ROOT, b.versioned_path);
    if (hash(b.path) !== b.sha256)
      throw Error("Versioned tool binary changed: " + b.path);
  }
  return result;
}
function projection(master, out) {
  const f = JSON.parse(fs.readFileSync(master)),
    t = tooling();
  if (f.stage !== "B1")
    throw Error("Only primary B1 can create calibration projection");
  if (fs.existsSync(out)) throw Error("Projection exists");
  const p = {
    schema: 4,
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
    window_definitions_sha256: t.window_definitions_sha256,
    longflow_definitions_sha256: t.longflow_definitions_sha256,
    ordering_semantics_sha256: t.ordering_semantics_sha256,
    coverage_semantics_sha256: t.coverage_semantics_sha256,
    observer_schema: 5,
    longflow_extractor_sha256: t.longflow.sha256,
    ensemble_binary_sha256: t.defender.sha256,
    score_engine_sha256: t.engine.sha256,
    observer_sha256: t.observer.sha256,
    observer_version: "g03-observer-v4",
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

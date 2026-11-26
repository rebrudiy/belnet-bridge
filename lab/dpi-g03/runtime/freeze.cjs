"use strict";
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const { tooling } = require("./tools.cjs");
const { ROOT, args, hash, save, sourceHashes } = require("./common.cjs");
function validate(file) {
  const f = JSON.parse(fs.readFileSync(file));
  if (f.schema !== "belnet-g03-collector/v1" || f.stage !== "B1")
    throw Error("Invalid collector freeze");
  if (
    !Array.isArray(f.groups) ||
    !f.groups.length ||
    f.groups.some((g) => !["train", "validation"].includes(g.split))
  )
    throw Error("B1 may acquire train/validation only");
  if (
    !Array.isArray(f.batches) ||
    f.batches.flat().length !== f.groups.length ||
    new Set(f.batches.flat()).size !== f.groups.length
  )
    throw Error("Invalid finite batches");
  for (const batch of f.batches) {
    const rows = batch.map((id) => f.groups.find((g) => g.group_id === id));
    if (
      rows.some((g) => !g) ||
      rows.length > 3 ||
      rows.filter((g) => g.class === "belnet").length > 1 ||
      new Set(rows.map((g) => g.source_workload_id)).size !== rows.length
    )
      throw Error("Invalid mixed-cohort resources");
  }
  for (const [p, h] of Object.entries(f.files_sha256 || {}))
    if (hash(path.resolve(ROOT, p)) !== h)
      throw Error("Frozen file changed: " + p);
  if (hash(f.prepared.path) !== f.prepared.sha256)
    throw Error("Prepared descriptor mismatch");
  if (hash(f.test_seeds_commitment.path) !== f.test_seeds_commitment.sha256)
    throw Error("Sealed test commitment changed");
  const prep = JSON.parse(fs.readFileSync(f.prepared.path));
  for (const [p, h] of Object.entries(prep.assets_sha256))
    if (hash(path.join(prep.directory, p)) !== h)
      throw Error("Prepared asset changed: " + p);
  for (const b of [prep.adapter, prep.sing_box, ...(prep.libraries || [])])
    if (hash(b.path) !== b.sha256) throw Error("Prepared ELF changed");
  return { freeze: f, prep, freeze_sha256: hash(file) };
}
function main() {
  const a = args(process.argv.slice(2));
  if (a.validate) {
    console.log(JSON.stringify({ valid: true, ...validate(a.validate) }));
    return;
  }
  const stage = a.stage || "B1",
    output = path.resolve(a.output || "lab/dpi-g03/run/freeze-b1.json");
  if (fs.existsSync(output)) throw Error("Freeze exists");
  if (stage !== "B1")
    throw Error(
      "B2 requires final-policy gate; not enabled before B1 development",
    );
  const prepPath = path.resolve(
      a.prepared || "lab/dpi-g03/run/prepared-b1/preparation.json",
    ),
    assign = path.resolve(a.assignments || "lab/dpi-g03/assignments.json");
  const raw = JSON.parse(fs.readFileSync(assign)),
    all = Array.isArray(raw) ? raw : raw.groups;
  if (!Array.isArray(all)) throw Error("Assignments require groups array");
  const ordered = raw.stages.B1.order.map((id) =>
    all.find((g) => g.group_id === id),
  );
  if (ordered.some((g) => !g)) throw Error("Invalid frozen order");
  const groups = ordered;
  if (groups.some((g) => !["train", "validation"].includes(g.split)))
    throw Error("Invalid split");
  const sealedFile = path.join(path.dirname(output), "private-test-seeds.json");
  if (fs.existsSync(sealedFile))
    throw Error("Private test commitment already exists");
  const seeds = {},
    sealed = {};
  for (const g of all.filter((g) => g.split === "test")) {
    if (!seeds[g.source_workload_id])
      seeds[g.source_workload_id] =
        crypto.randomBytes(6).readUIntBE(0, 6) % (2 ** 48 - 10000) || 1;
    sealed[g.group_id] = {
      seed_int: seeds[g.source_workload_id],
      nonce: crypto.randomBytes(32).toString("hex"),
      initial_nonce: crypto.randomBytes(32).toString("hex"),
      warmup_nonces: [0, 1, 2].map(() =>
        crypto.randomBytes(32).toString("hex"),
      ),
    };
  }
  save(sealedFile, sealed);
  const files = { ...sourceHashes() };
  const controls = JSON.parse(
    fs.readFileSync("out/dpi-g03/tooling/v2/preparation.json"),
  );
  for (const [p, h] of Object.entries(controls.source_files_sha256)) {
    const file = path.join("lab/dpi-g03/controls", p);
    if (hash(file) !== h) throw Error("Control source changed: " + file);
    files[file] = h;
  }
  const t = tooling();
  for (const b of [t.observer, t.defender, t.engine])
    files[path.relative(ROOT, b.path)] = b.sha256;
  for (const manifest of [
    "out/dpi-g03/tooling-observer/TOOLING.json",
    "out/dpi-g03/tooling-defender/TOOLING.json",
  ]) {
    const m = JSON.parse(fs.readFileSync(manifest));
    for (const [p, h] of Object.entries(m.source_sha256 || {})) {
      if (hash(p) !== h) throw Error("Tooling source changed: " + p);
      files[p] = h;
    }
  }
  for (const p of [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome.app/Contents/Info.plist",
    "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Google Chrome Framework",
  ])
    files[p] = hash(p);
  for (const p of [
    prepPath,
    assign,
    path.join(ROOT, "lab/dpi-g03/PROTOCOL.md"),
    "out/dpi-g03/tooling/v2/preparation.json",
    "out/dpi-g03/tooling-observer/TOOLING.json",
    "out/dpi-g03/tooling-defender/TOOLING.json",
  ])
    files[path.relative(ROOT, path.resolve(p))] = hash(p);
  const adapterFreezePath = path.join(ROOT, "lab/dpi-g02/run/freeze-a2.json");
  const adapterFreeze = JSON.parse(fs.readFileSync(adapterFreezePath));
  const archive = path.join(path.dirname(output), "frozen-b1-source");
  if (fs.existsSync(archive)) throw Error("Source archive already exists");
  for (const [p, h] of Object.entries(adapterFreeze.adapter_source_sha256)) {
    if (hash(path.join(ROOT, p)) !== h)
      throw Error("A2 adapter source drift: " + p);
    files[p] = h;
  }
  files["lab/dpi-g02/run/freeze-a2.json"] = hash(adapterFreezePath);
  files[path.relative(ROOT, adapterFreeze.build.log.path)] = hash(
    adapterFreeze.build.log.path,
  );
  for (const [p, h] of Object.entries(files)) {
    if (path.isAbsolute(p) || !/\.(?:cjs|sh|go|mod|sum|md|json|log)$/.test(p))
      continue;
    const target = path.join(archive, p);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(ROOT, p), target);
    if (hash(target) !== h) throw Error("Archive mismatch");
  }
  const f = {
    schema: "belnet-g03-collector/v1",
    stage,
    run_id: a["run-id"] || "b1-20261119",
    frozen_at: new Date().toISOString(),
    prepared: { path: prepPath, sha256: hash(prepPath) },
    assignments: { path: assign, sha256: hash(assign) },
    groups,
    batches: raw.stages.B1.batches,
    max_active_groups: raw.resource_limits.max_active_groups,
    test_seeds_commitment: {
      path: sealedFile,
      sha256: hash(sealedFile),
      test_groups: Object.keys(sealed).length,
    },
    files_sha256: files,
    source_archive: archive,
    measured_seconds: 80,
    capture_seconds: 82,
    prefix_grace_seconds: 2,
    window_offsets_seconds: [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78],
    pcap_cap_bytes: 268435456,
    old_tests_development_only: true,
  };
  save(output, f);
  validate(output);
  console.log(
    JSON.stringify({
      freeze: output,
      sha256: hash(output),
      groups: groups.length,
      real_traffic_started: false,
    }),
  );
}
if (require.main === module)
  try {
    main();
  } catch (e) {
    console.error(e.stack);
    process.exitCode = 1;
  }
module.exports = { validate, main };

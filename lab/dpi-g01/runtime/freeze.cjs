"use strict";
// OFFLINE ONLY. Lead supplies actual build and live-baseline evidence.
const fs = require("fs"),
  path = require("path");
const {
  ROOT,
  args,
  hash,
  save,
  sourceHashes,
  adapterSourceHashes,
} = require("./common.cjs");
const { validateFreeze } = require("./stage-a.cjs");
function main() {
  const a = args(process.argv.slice(2));
  for (const key of [
    "adapter",
    "build-evidence",
    "baseline-evidence",
    "run-id",
  ])
    if (!a[key]) throw Error("--" + key + " required");
  const prepared = path.resolve(
      a.prepared || "lab/dpi-g01/run/prepared-a/preparation.json",
    ),
    adapter = path.resolve(a.adapter),
    build = JSON.parse(fs.readFileSync(path.resolve(a["build-evidence"]))),
    baselineDocument = JSON.parse(
      fs.readFileSync(path.resolve(a["baseline-evidence"])),
    ),
    servers = Array.isArray(baselineDocument)
      ? baselineDocument
      : baselineDocument.servers;
  if (
    !Array.isArray(servers) ||
    servers.length !== 2 ||
    servers.some((s) => s.enforce !== false)
  )
    throw Error("Actual two baseline server records must attest enforce:false");
  const output = path.resolve(
    a.output || "out/dpi-g01/runtime-preparation/freeze-a.json",
  );
  if (fs.existsSync(output))
    throw Error(
      "Refusing to overwrite freeze; use a new output after explicit review",
    );
  const freeze = {
    schema: "belnet-g01-stage-a/v1",
    stage: "A",
    run_id: a["run-id"],
    frozen_at: new Date().toISOString(),
    protocol_sha256: hash(path.join(ROOT, "lab/dpi-g01/PROTOCOL.md")),
    plan_sha256: hash(path.join(__dirname, "plan.json")),
    source_sha256: sourceHashes(),
    adapter_source_sha256: adapterSourceHashes(),
    prepared: { path: prepared, sha256: hash(prepared) },
    adapter: { path: adapter, sha256: hash(adapter) },
    build,
    baseline_servers: servers,
    baseline_enforcement_disabled: true,
  };
  const temporary = output + ".pending";
  save(temporary, freeze);
  try {
    validateFreeze(temporary);
    fs.renameSync(temporary, output);
  } catch (e) {
    fs.rmSync(temporary, { force: true });
    throw e;
  }
  console.log(
    JSON.stringify({
      freeze: output,
      sha256: hash(output),
      real_traffic_started: false,
    }),
  );
}
if (require.main === module)
  try {
    main();
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
module.exports = { main };

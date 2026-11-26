"use strict";
// Offline configuration only: containers are network-none and do not collect B data.
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const { ROOT, args, exec, hash, save, coreConfigs } = require("./common.cjs");
async function main() {
  const a = args(process.argv.slice(2)),
    dir = path.resolve(a.directory || "lab/dpi-g03/run/prepared-b1-r2");
  if (fs.existsSync(dir))
    throw Error("Refusing to overwrite prepared directory");
  fs.mkdirSync(path.join(dir, "private"), { recursive: true });
  fs.mkdirSync(path.join(dir, "bin"));
  fs.mkdirSync(path.join(dir, "public"));
  const image = "belnet-bridge:dpi-v2",
    sing = path.resolve("out/dpi-v2/mature/bin/sing-box"),
    tools = path.resolve("out/dpi-g03/tooling/v2/bin");
  const entries = [];
  for (let n = 1; n <= 2; n++) {
    const r = await exec([
      "docker",
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      path.dirname(sing) + ":/mature:ro",
      image,
      "/mature/sing-box",
      "generate",
      "reality-keypair",
    ]);
    const k = Object.fromEntries(
      r.stdout
        .trim()
        .split("\n")
        .map((l) => {
          const p = l.indexOf(":");
          return [
            l.slice(0, p).toLowerCase().replace(/\s/g, ""),
            l.slice(p + 1).trim(),
          ];
        }),
    );
    entries.push({
      private_key: k.privatekey || k.private,
      public_key: k.publickey || k.public,
      uuid: crypto.randomUUID(),
      short_id: crypto.randomBytes(4).toString("hex"),
    });
    if (!entries.at(-1).private_key || !entries.at(-1).public_key)
      throw Error("Key format changed");
  }
  save(path.join(dir, "private/credentials.json"), entries);
  await exec([
    "docker",
    "run",
    "--rm",
    "--network",
    "none",
    "-v",
    tools + ":/tools:ro",
    "-v",
    dir + ":/prep",
    image,
    "/tools/bench-cert",
    "-directory",
    "/prep/private/tls",
    "-hosts",
    "decoy.test,entry1.test,entry2.test",
  ]);
  fs.copyFileSync(
    path.join(ROOT, "lab/run/certs/token"),
    path.join(dir, "private/bridge-token"),
  );
  fs.chmodSync(path.join(dir, "private/bridge-token"), 0o600);
  for (const name of ["bench-server", "bench-client"])
    fs.copyFileSync(path.join(tools, name), path.join(dir, "bin", name));
  const quiesce = JSON.parse(
    fs.readFileSync(path.join(ROOT, "lab/dpi-g03/quiesce-proxy/TOOLING.json")),
  );
  if (hash(quiesce.binary.path) !== quiesce.binary.sha256)
    throw Error("Quiesce binary changed");
  fs.copyFileSync(quiesce.binary.path, path.join(dir, "bin/connect-proxy"));
  fs.copyFileSync(
    path.join(ROOT, "lab/dpi-g02/run/prepared-a/bin/probe"),
    path.join(dir, "bin/probe"),
  );
  const config = coreConfigs(entries, "10.88.0.60");
  const checks = [];
  for (let n = 1; n <= 2; n++)
    save(path.join(dir, "private/entry" + n + ".json"), config.servers[n]);
  save(path.join(dir, "private/client-check.json"), config.client);
  for (const file of ["entry1.json", "entry2.json", "client-check.json"]) {
    const r = await exec([
      "docker",
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      path.dirname(sing) + ":/mature:ro",
      "-v",
      dir + ":/prep:ro",
      image,
      "/mature/sing-box",
      "check",
      "-c",
      "/prep/private/" + file,
    ]);
    checks.push({ file, ...r });
  }
  const controls = JSON.parse(
    fs.readFileSync("out/dpi-g03/tooling/v2/preparation.json"),
  );
  for (const name of ["bench-server", "bench-client"])
    if (hash(path.join(dir, "bin", name)) !== controls.binaries[name].sha256)
      throw Error("Untested control binary: " + name);
  for (const peer of [
    "seed",
    "entry1",
    "entry2",
    "relay1",
    "relay2",
    "relay3",
  ]) {
    const dest = path.join(dir, "fixtures", peer);
    fs.mkdirSync(dest, { recursive: true });
    fs.copyFileSync(
      path.join(ROOT, "lab/run", peer, "self.signed"),
      path.join(dest, "self.signed"),
    );
  }
  const assets = {};
  const walk = (p) => {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      const f = path.join(p, e.name);
      if (e.isDirectory()) walk(f);
      else assets[path.relative(dir, f)] = hash(f);
    }
  };
  walk(dir);
  const runtimeImage = (
    await exec(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
  ).stdout.trim();
  const adapter = path.resolve("lab/dpi-g02/bin/belnet-bridge-a2-v1");
  const desc = {
    schema: "belnet-g03-preparation/v1",
    prepared_at: new Date().toISOString(),
    directory: dir,
    runtime_image: runtimeImage,
    assets_sha256: assets,
    config_checks: checks,
    adapter: { path: adapter, sha256: hash(adapter) },
    sing_box: { path: sing, directory: path.dirname(sing), sha256: hash(sing) },
    quiesce_descriptor: {
      path: path.join(ROOT, "lab/dpi-g03/quiesce-proxy/TOOLING.json"),
      sha256: hash(path.join(ROOT, "lab/dpi-g03/quiesce-proxy/TOOLING.json")),
    },
    controls_descriptor: {
      path: path.resolve("out/dpi-g03/tooling/v2/preparation.json"),
      sha256: hash("out/dpi-g03/tooling/v2/preparation.json"),
    },
    native_belnet: {
      path: "/usr/local/bin/belnet",
      sha256: (
        await exec([
          "docker",
          "run",
          "--rm",
          "--network",
          "none",
          image,
          "sha256sum",
          "/usr/local/bin/belnet",
        ])
      ).stdout
        .trim()
        .split(/\s+/)[0],
    },
    libraries: fs.existsSync(path.join(path.dirname(sing), "libcronet.so"))
      ? [
          {
            path: path.join(path.dirname(sing), "libcronet.so"),
            sha256: hash(path.join(path.dirname(sing), "libcronet.so")),
          },
        ]
      : [],
    adapter_source_provenance:
      "out/dpi-g01/root-review/frozen-a-r2/MANIFEST.json plus G02 frozen source hashes/build log in lab/dpi-g02/run/freeze-a2.json",
    real_traffic_started: false,
  };
  save(path.join(dir, "preparation.json"), desc);
  console.log(
    JSON.stringify({
      prepared: path.join(dir, "preparation.json"),
      sha256: hash(path.join(dir, "preparation.json")),
    }),
  );
}
if (require.main === module)
  main().catch((e) => {
    console.error(e.stack);
    process.exitCode = 1;
  });
module.exports = { main };

"use strict";
// OFFLINE ONLY: key generation, compilation, config validation; no traffic run.
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const { ROOT, hash, save, exec, args, buildConfigs } = require("./common.cjs");
async function main() {
  const a = args(process.argv.slice(2)),
    directory = path.resolve(a.directory || "lab/dpi-g01/run/prepared-a"),
    image = a.image || "belnet-bridge:dpi-v2",
    sing = path.resolve(a.singbox || "out/dpi-v2/mature/bin/sing-box");
  if (fs.existsSync(path.join(directory, "preparation.json")))
    throw Error("Refusing to overwrite prepared credentials");
  fs.mkdirSync(path.join(directory, "private"), { recursive: true });
  fs.mkdirSync(path.join(directory, "public"), { recursive: true });
  fs.mkdirSync(path.join(directory, "bin"), { recursive: true });
  const entries = [];
  for (let n = 1; n <= 2; n++) {
    const generated = await exec([
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
    const keys = Object.fromEntries(
      generated.stdout
        .trim()
        .split("\n")
        .map((line) => {
          const i = line.indexOf(":");
          return [
            line.slice(0, i).toLowerCase().replace(/\s/g, ""),
            line.slice(i + 1).trim(),
          ];
        }),
    );
    entries.push({
      private_key: keys.privatekey || keys.private,
      public_key: keys.publickey || keys.public,
      uuid: crypto.randomUUID(),
      short_id: crypto.randomBytes(4).toString("hex"),
    });
    if (!entries.at(-1).private_key || !entries.at(-1).public_key)
      throw Error("REALITY key generator format changed");
    await exec([
      "docker",
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      directory + ":/prep",
      image,
      "openssl",
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      "/prep/private/entry" + n + ".key",
      "-out",
      "/prep/private/entry" + n + ".crt",
      "-days",
      "1",
      "-subj",
      "/CN=decoy.test",
      "-addext",
      "subjectAltName=DNS:decoy.test",
    ]);
  }
  const configs = buildConfigs({ entries });
  save(path.join(directory, "private/client.json"), configs.client);
  for (let n = 1; n <= 2; n++)
    save(
      path.join(directory, "private/entry" + n + ".json"),
      configs.server[n],
    );
  fs.copyFileSync(
    path.join(ROOT, "lab/run/certs/token"),
    path.join(directory, "private/bridge-token"),
  );
  fs.chmodSync(path.join(directory, "private/bridge-token"), 0o600);
  for (const [from, to] of [
    ["lab/run/certs/ca.crt", "ca.crt"],
    ["lab/crosscheck/run/frozen-profile.json", "v2-profile.json"],
  ])
    fs.copyFileSync(path.join(ROOT, from), path.join(directory, "public", to));
  const probe = path.join(directory, "bin/probe");
  await exec(
    [
      "env",
      "GOOS=linux",
      "GOARCH=arm64",
      "CGO_ENABLED=0",
      "go",
      "build",
      "-trimpath",
      "-o",
      probe,
      "./lab/dpi-g01/runtime/cmd/probe",
    ],
    { timeout: 60000 },
  );
  const checks = [];
  for (const file of [
    "private/client.json",
    "private/entry1.json",
    "private/entry2.json",
  ])
    checks.push({
      file,
      ...(await exec([
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        directory + ":/prep:ro",
        "-v",
        path.dirname(sing) + ":/mature:ro",
        image,
        "/mature/sing-box",
        "check",
        "-c",
        "/prep/" + file,
      ])),
    });
  const imageID = (
    await exec(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
  ).stdout.trim();
  const assets = {};
  for (const file of [
    "private/client.json",
    "private/entry1.json",
    "private/entry2.json",
    "private/entry1.key",
    "private/entry1.crt",
    "private/entry2.key",
    "private/entry2.crt",
    "private/bridge-token",
    "public/ca.crt",
    "public/v2-profile.json",
    "bin/probe",
  ])
    assets[file] = hash(path.join(directory, file));
  const nativeHash = (
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
    .split(/\s+/)[0];
  const descriptor = {
    native_belnet: {
      path: "/usr/local/bin/belnet",
      sha256: nativeHash,
      image: imageID,
    },
    schema: "belnet-g01-prepared/v1",
    prepared_at: new Date().toISOString(),
    directory,
    runtime_image: imageID,
    sing_box: {
      path: sing,
      directory: path.dirname(sing),
      sha256: hash(sing),
      libraries: fs.existsSync(path.join(path.dirname(sing), "libcronet.so"))
        ? [
            {
              path: path.join(path.dirname(sing), "libcronet.so"),
              sha256: hash(path.join(path.dirname(sing), "libcronet.so")),
            },
          ]
        : [],
    },
    probe: { path: probe, sha256: hash(probe) },
    assets_sha256: assets,
    config_checks: checks.map((x) => ({
      file: x.file,
      code: x.code,
      stdout: x.stdout,
      stderr: x.stderr,
    })),
    real_traffic_started: false,
  };
  save(path.join(directory, "preparation.json"), descriptor);
  save(
    path.join(ROOT, "out/dpi-g01/runtime-preparation/preparation.json"),
    descriptor,
  );
  console.log(
    JSON.stringify({
      prepared: path.join(directory, "preparation.json"),
      sha256: hash(path.join(directory, "preparation.json")),
      offline_config_checks: checks.length,
    }),
  );
}
if (require.main === module)
  main().catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
module.exports = { main };

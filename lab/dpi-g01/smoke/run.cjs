"use strict";
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process"),
  crypto = require("crypto");
const ROOT = path.resolve(__dirname, "../../.."),
  ADAPTER = path.join(ROOT, "lab/dpi-g01/bin/belnet-bridge"),
  EXPECTED = "8f6cf237aba6c1174d705a0f9dbe8257c9e09c09bfd9f41dbd9bab3909138bd8";
const hash = (p) =>
  crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const save = (p, v) => {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(v, null, 2) + "\n", { mode: 0o600 });
};
function call(args, { timeout = 30000, allowFailure = false } = {}) {
  const p = cp.spawnSync(args[0], args.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    timeout,
    maxBuffer: 16 * 1024 * 1024,
  });
  const r = {
    code: p.status,
    signal: p.signal,
    stdout: p.stdout || "",
    stderr: p.stderr || "",
    error: p.error ? String(p.error) : undefined,
  };
  if (r.code !== 0 && !allowFailure)
    throw Object.assign(
      Error(args.slice(0, 3).join(" ") + ": " + r.stderr.slice(-2000)),
      { result: r },
    );
  return r;
}
function sourceHashes() {
  const out = {};
  function walk(p) {
    for (const d of fs.readdirSync(p, { withFileTypes: true })) {
      const f = path.join(p, d.name);
      if (d.isDirectory()) walk(f);
      else if (/\.(go|cjs|sh|md)$/.test(f))
        out[path.relative(ROOT, f)] = hash(f);
    }
  }
  walk(__dirname);
  return out;
}
function main() {
  const id =
    process.argv[2] ||
    new Date()
      .toISOString()
      .replace(/[^0-9]/g, "")
      .slice(0, 17);
  if (!/^[a-z0-9-]{1,40}$/.test(id)) throw Error("Invalid run ID");
  const run = path.join(ROOT, "lab/dpi-g01/run/smoke-" + id),
    out = path.join(ROOT, "out/dpi-g01/smoke", id),
    name = "bb-g01-smoke-" + id;
  if (fs.existsSync(run))
    throw Error("Refusing to reuse smoke run or reroll measured attempts");
  fs.mkdirSync(path.join(run, "private"), { recursive: true });
  fs.mkdirSync(path.join(run, "bin"), { recursive: true });
  fs.mkdirSync(out, { recursive: true });
  let launched = false;
  try {
    if (hash(ADAPTER) !== EXPECTED)
      throw Error("Root frozen adapter SHA mismatch");
    const descriptorPath = path.join(
        ROOT,
        "lab/dpi-g01/run/prepared-a/preparation.json",
      ),
      prep = JSON.parse(fs.readFileSync(descriptorPath));
    for (const [file, h] of Object.entries(prep.assets_sha256))
      if (hash(path.join(prep.directory, file)) !== h)
        throw Error("Prepared lineage changed");
    const originalServer = JSON.parse(
        fs.readFileSync(path.join(prep.directory, "private/entry1.json")),
      ),
      originalClient = JSON.parse(
        fs.readFileSync(path.join(prep.directory, "private/client.json")),
      ),
      server = structuredClone(originalServer),
      client = structuredClone(originalClient);
    server.inbounds[0].listen = "127.0.0.1";
    client.inbounds = client.inbounds.filter((x) => x.tag === "tcp-entry1");
    client.outbounds = [client.outbounds[0]];
    client.outbounds[0].server = "127.0.0.1";
    client.route.rules = client.route.rules.filter(
      (x) => !x.inbound || x.inbound.includes("tcp-entry1"),
    );
    save(path.join(run, "private/server.json"), server);
    save(path.join(run, "private/client.json"), client);
    const compile = call(
      [
        "env",
        "GOOS=linux",
        "GOARCH=arm64",
        "CGO_ENABLED=0",
        "go",
        "build",
        "-trimpath",
        "-o",
        path.join(run, "bin/check"),
        "./lab/dpi-g01/smoke/cmd/check",
      ],
      { timeout: 60000 },
    );
    save(path.join(out, "build.json"), compile);
    const checks = [];
    for (const config of ["server", "client"])
      checks.push({
        config,
        ...call([
          "docker",
          "run",
          "--rm",
          "--network",
          "none",
          "-v",
          run + ":/work:ro",
          "-v",
          prep.sing_box.directory + ":/mature:ro",
          prep.runtime_image,
          "/mature/sing-box",
          "check",
          "-c",
          "/work/private/" + config + ".json",
        ]),
      });
    const manifest = {
      schema: "g01-isolated-reality-smoke/v1",
      frozen_at: new Date().toISOString(),
      run_id: id,
      native_belnet: false,
      fixture_only: true,
      network: "none; loopback only",
      cpu_limit: 1,
      memory_limit: "512m",
      max_core_processes: 2,
      adapter: { path: ADAPTER, sha256: EXPECTED },
      helper: { sha256: hash(path.join(run, "bin/check")) },
      runtime_image: prep.runtime_image,
      sing_box: prep.sing_box,
      prepared: { path: descriptorPath, sha256: hash(descriptorPath) },
      config_sha256: {
        server: hash(path.join(run, "private/server.json")),
        client: hash(path.join(run, "private/client.json")),
      },
      config_changes: [
        "Server REALITY listen127.0.0.1 instead entryIP",
        "Client entry1 only, REALITY server127.0.0.1",
        "Same prepared REALITY keys, UUID, shortID, Chrome fingerprint, fixed TCP127.0.0.1:21990 rule",
        "Go framed server fixed UDP target127.0.0.1:12090 echo fixture, not native1090",
      ],
      source_sha256: sourceHashes(),
      plan: {
        sizes: [0, 1, 1200, 60000, 65507],
        phase_order: [
          "one stable UDP source: all five exact payloads",
          "stop client core, wait for exit, absent2s, start",
          "same UDP source: all five exact payloads",
          "second UDP source:128bytes,distinctSID/tuple",
          "bad-token Go client:256bytes,timeout1s, no newUDPstate",
        ],
        retry_until_success: false,
        datagram_timeout_seconds: 5,
        overall_timeout_seconds: 90,
        capture: "Only loopback TCP19444 ciphertext; plaintext21990 excluded",
      },
    };
    save(path.join(run, "freeze.json"), manifest);
    save(path.join(out, "freeze.json"), manifest);
    const frozenHash = hash(path.join(run, "freeze.json"));
    call([
      "docker",
      "run",
      "-d",
      "--name",
      name,
      "--network",
      "none",
      "--cpus",
      "1",
      "--memory",
      "512m",
      "-v",
      run + ":/work",
      "-v",
      prep.directory + ":/prep:ro",
      "-v",
      prep.sing_box.directory + ":/mature:ro",
      "-v",
      ADAPTER + ":/bridge:ro",
      "-v",
      __dirname + ":/smoke:ro",
      "--entrypoint",
      "/bin/sh",
      prep.runtime_image,
      "/smoke/start.sh",
    ]);
    launched = true;
    const wait = call(["docker", "wait", name], {
      timeout: 90000,
      allowFailure: true,
    });
    save(path.join(out, "wait.json"), wait);
    const inspect = JSON.parse(call(["docker", "inspect", name]).stdout)[0];
    save(path.join(out, "runtime.json"), {
      state: inspect.State,
      network: inspect.HostConfig.NetworkMode,
      nano_cpus: inspect.HostConfig.NanoCpus,
      memory: inspect.HostConfig.Memory,
      freeze_sha256: frozenHash,
      freeze_precedes_start:
        Date.parse(manifest.frozen_at) <= Date.parse(inspect.State.StartedAt),
    });
    if (hash(path.join(run, "freeze.json")) !== frozenHash)
      throw Error("Manifest mutated during run");
    if (wait.code !== 0) {
      call(["docker", "kill", name], { allowFailure: true });
      save(path.join(out, "incomplete.json"), {
        reason: "overall deadline/process wait failed",
        wait,
      });
    }
  } catch (e) {
    save(path.join(out, "failure.json"), {
      error: e.message,
      process: e.result,
      at: new Date().toISOString(),
    });
    process.exitCode = 1;
  } finally {
    if (launched) {
      const logs = call(["docker", "logs", name], { allowFailure: true });
      fs.writeFileSync(
        path.join(out, "container.log"),
        logs.stdout + logs.stderr,
      );
      call(["docker", "rm", "-f", name], { allowFailure: true });
    }
    for (const file of fs.readdirSync(run)) {
      if (/\.(json|jsonl|log|pcap)$/.test(file))
        fs.copyFileSync(path.join(run, file), path.join(out, file));
    }
    const artifacts = {};
    for (const file of fs
      .readdirSync(out)
      .filter(
        (f) =>
          fs.statSync(path.join(out, f)).isFile() && f !== "artifacts.json",
      ))
      artifacts[file] = hash(path.join(out, file));
    save(path.join(out, "artifacts.json"), artifacts);
    let result = null;
    try {
      result = JSON.parse(fs.readFileSync(path.join(out, "result.json")));
    } catch {}
    console.log(
      JSON.stringify({
        out,
        native_belnet: false,
        passed: result?.passed || false,
        before: result?.exact_before,
        after: result?.exact_after,
        tuple: result?.primary_tuple_sid_preserved,
        two_sid: result?.second_sid_isolated,
        bad_token: result?.bad_token_no_udp_state,
        attempts: result?.attempts?.length,
      }),
    );
  }
}
if (require.main === module) main();

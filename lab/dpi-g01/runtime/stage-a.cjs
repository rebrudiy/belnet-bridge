"use strict";
const fs = require("fs"),
  path = require("path");
const {
  ROOT,
  hash,
  save,
  exec,
  args,
  sourceHashes,
  adapterSourceHashes,
} = require("./common.cjs");
const { Capture } = require("./capture.cjs");
const PLAN = require("./plan.json");
const delay = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
const since = (start) => performance.now() - start;
async function at(start, ms, fn) {
  await delay(ms - since(start));
  return fn();
}
function validateFreeze(file) {
  const freeze = JSON.parse(fs.readFileSync(file));
  if (
    freeze.schema !== "belnet-g01-stage-a/v1" ||
    freeze.stage !== "A" ||
    !freeze.frozen_at ||
    !/^[-a-z0-9]{1,40}$/.test(freeze.run_id || "")
  )
    throw Error("Invalid frozen stage-A manifest");
  if (
    freeze.protocol_sha256 !==
      hash(path.join(ROOT, "lab/dpi-g01/PROTOCOL.md")) ||
    freeze.plan_sha256 !== hash(path.join(__dirname, "plan.json"))
  )
    throw Error("Protocol or finite plan changed after freeze");
  const sources = sourceHashes();
  if (
    JSON.stringify(Object.keys(sources).sort()) !==
    JSON.stringify(Object.keys(freeze.source_sha256 || {}).sort())
  )
    throw Error("Frozen source set differs");
  for (const [file, h] of Object.entries(sources))
    if (freeze.source_sha256[file] !== h)
      throw Error("Source changed: " + file);
  if (!freeze.baseline_enforcement_disabled)
    throw Error(
      "Lead must attest old baseline enforcement disabled before freeze",
    );
  if (
    !Array.isArray(freeze.baseline_servers) ||
    freeze.baseline_servers.length !== 2 ||
    freeze.baseline_servers.some(
      (x) => !/^([a-f0-9]{64})$/.test(x.live_binary_sha256 || ""),
    )
  )
    throw Error("Two actual live baseline-server binary SHA values required");
  if (
    !freeze.prepared?.path ||
    hash(freeze.prepared.path) !== freeze.prepared.sha256
  )
    throw Error("Prepared descriptor mismatch");
  const adapterSources = adapterSourceHashes();
  if (
    JSON.stringify(Object.keys(adapterSources).sort()) !==
    JSON.stringify(Object.keys(freeze.adapter_source_sha256 || {}).sort())
  )
    throw Error("Adapter source set differs");
  for (const [file, h] of Object.entries(adapterSources))
    if (freeze.adapter_source_sha256[file] !== h)
      throw Error("Adapter source changed: " + file);
  if (
    !Array.isArray(freeze.build?.command) ||
    !freeze.build.command.length ||
    !freeze.build.log?.path ||
    hash(freeze.build.log.path) !== freeze.build.log.sha256
  )
    throw Error("Frozen build command/log required");
  const prep = JSON.parse(fs.readFileSync(freeze.prepared.path));
  if (!/^[a-f0-9]{64}$/.test(prep.native_belnet?.sha256 || ""))
    throw Error("Actual native binary SHA required");
  for (const [file, h] of Object.entries(prep.assets_sha256))
    if (hash(path.join(prep.directory, file)) !== h)
      throw Error("Prepared asset changed: " + file);
  for (const lib of prep.sing_box.libraries || [])
    if (hash(lib.path) !== lib.sha256) throw Error("Runtime library changed");
  for (const b of [freeze.adapter, prep.probe, prep.sing_box]) {
    if (!b?.path || !b.sha256 || hash(b.path) !== b.sha256)
      throw Error("Actual binary SHA missing/mismatch");
    const fd = fs.openSync(b.path, "r"),
      magic = Buffer.alloc(4);
    fs.readSync(fd, magic, 0, 4, 0);
    fs.closeSync(fd);
    if (magic.toString("hex") !== "7f454c46")
      throw Error("Runtime binary is not Linux ELF");
  }
  return { freeze, prep, freeze_sha256: hash(file) };
}
async function main() {
  const a = args(process.argv.slice(2));
  if (!a.freeze)
    throw Error(
      "A frozen manifest with actual binary SHA is required before any run",
    );
  const checked = validateFreeze(path.resolve(a.freeze));
  if (a["validate-only"] === "true") {
    console.log(
      JSON.stringify({
        valid: true,
        freeze_sha256: checked.freeze_sha256,
        real_traffic_started: false,
      }),
    );
    return;
  }
  const { freeze, prep } = checked;
  const output = path.join(ROOT, "lab/dpi-g01/run/stage-a-" + freeze.run_id);
  if (fs.existsSync(output))
    throw Error("Refusing to overwrite native identities/run data");
  const old = await exec(
    ["docker", "inspect", "bb-dpi-v2-client", "--format", "{{.State.Running}}"],
    { allowFailure: true },
  );
  if (old.stdout.trim() === "true")
    throw Error(
      "Lead must stop old checkpoint client; harness will not touch it",
    );
  for (const name of [
    "bb-lab-entry1-1",
    "bb-lab-entry2-1",
    "bb-lab-service-1",
  ]) {
    const p = await exec([
      "docker",
      "inspect",
      name,
      "--format",
      "{{.State.Running}}",
    ]);
    if (p.stdout.trim() !== "true")
      throw Error("Existing native dependency not running: " + name);
  }
  const existing = (
    await exec(["docker", "ps", "-a", "--format", "{{.Names}}"])
  ).stdout
    .split("\n")
    .filter((n) => n.startsWith("bb-g01-"));
  if (existing.length)
    throw Error(
      "Existing bb-g01 containers must be reviewed, not overwritten: " +
        existing.join(","),
    );
  fs.mkdirSync(output, { recursive: true });
  save(path.join(output, "run-start.json"), {
    ...checked,
    started: new Date().toISOString(),
    plan: PLAN,
  });
  const globalCreated = [];
  const image = prep.runtime_image,
    binds = [
      "-v",
      prep.directory + ":/prep:ro",
      "-v",
      freeze.adapter.path + ":/bridge:ro",
      "-v",
      path.join(ROOT, "lab") + ":/lab",
    ];
  const create = async (name, options, command, owned) => {
    owned.push(name);
    await exec([
      "docker",
      "run",
      "-d",
      "--name",
      name,
      ...options,
      ...binds,
      "--entrypoint",
      "/bin/sh",
      image,
      "-c",
      command,
    ]);
  };
  const admin = async (container, port, method, route, body) => {
    const result = await exec(
      [
        "docker",
        "exec",
        "-i",
        container,
        "/prep/bin/probe",
        "admin",
        method,
        "http://127.0.0.1:" + port + route,
      ],
      {
        input: body ? JSON.stringify(body) : undefined,
        timeout: 4000,
        allowFailure: true,
      },
    );
    try {
      return {
        ok: result.code === 0,
        data: JSON.parse(result.stdout),
        stderr: result.stderr,
      };
    } catch {
      return { ok: false, ...result };
    }
  };
  const archiveRemove = async (names, dir) => {
    for (const name of [...names].reverse()) {
      const logs = await exec(["docker", "logs", name], { allowFailure: true });
      fs.writeFileSync(
        path.join(dir, name + ".log"),
        logs.stdout + logs.stderr,
      );
      if (name === "bb-g01-service-helper")
        fs.writeFileSync(
          path.join(dir, "service.log"),
          logs.stdout + logs.stderr,
        );
      await exec(["docker", "rm", "-f", name], { allowFailure: true });
    }
  };
  try {
    await create(
      "bb-g01-service-helper",
      ["--network", "container:bb-lab-service-1"],
      "exec /prep/bin/probe serve",
      globalCreated,
    );
    for (let n = 1; n <= 2; n++) {
      const network = ["--network", "container:bb-lab-entry" + n + "-1"];
      await create(
        "bb-g01-entry" + n + "-shim",
        network,
        "BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN; exec /bridge udp-stream-server -listen 127.0.0.1:21990 -target 10.88.0.1" +
          n +
          ":1090 -lab-control 127.0.0.1:2291",
        globalCreated,
      );
      await create(
        "bb-g01-entry" + n + "-core",
        [
          ...network,
          "-v",
          prep.sing_box.directory + ":/mature:ro",
          "-v",
          output + ":/record",
        ],
        "openssl s_server -accept 127.0.0.1:18444 -cert /prep/private/entry" +
          n +
          ".crt -key /prep/private/entry" +
          n +
          ".key -www -tls1_3 > /record/entry" +
          n +
          "-decoy.log 2>&1 & exec /mature/sing-box run -c /prep/private/entry" +
          n +
          ".json",
        globalCreated,
      );
    }
    const trials = [];
    for (const group of PLAN.groups) {
      const dir = path.join(output, group.id),
        owned = [],
        captures = [];
      fs.mkdirSync(dir);
      const nativeName = "bb-g01-" + freeze.run_id + "-" + group.id,
        coreName = nativeName + "-core";
      const record = {
        group,
        started: new Date().toISOString(),
        warmup: [],
        proofs: [],
        snapshots: [],
        interruption: null,
        errors: [],
      };
      save(path.join(dir, "assignment.json"), group);
      let finished = false;
      try {
        await create(
          nativeName,
          [
            "--network",
            "bb-lab_private",
            "--ip",
            PLAN.client_ip,
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            ...[
              "all.route_localnet=1",
              "lo.route_localnet=1",
              "all.accept_local=1",
              "lo.accept_local=1",
              "all.rp_filter=0",
              "lo.rp_filter=0",
            ].flatMap((x) => ["--sysctl", "net.ipv4.conf." + x]),
            "-v",
            dir + ":/group",
            "-e",
            "G01_KIND=" + group.kind,
          ],
          "exec /bin/sh /lab/dpi-g01/runtime/client.sh",
          owned,
        );
        if (group.kind === "framed")
          await create(
            coreName,
            [
              "--network",
              "container:" + nativeName,
              "-v",
              prep.sing_box.directory + ":/mature:ro",
            ],
            "exec /mature/sing-box run -c /prep/private/client.json",
            owned,
          );
        const outer = new Capture({
          name: nativeName + "-capture",
          network: nativeName,
          image,
          directory: dir,
          file: "outer.pcap",
          filter: [
            "tcp",
            "port",
            group.kind === "v2" ? "443" : "19444",
            "or",
            "udp",
            "port",
            "1090",
          ],
          maxBytes: PLAN.pcap_max_bytes,
        });
        owned.push(outer.name);
        captures.push(outer);
        await outer.ready();
        for (let n = 1; n <= 2; n++) {
          const c = new Capture({
            name: nativeName + "-udp" + n,
            network: "bb-lab-entry" + n + "-1",
            image,
            directory: dir,
            file: "entry" + n + "-udp.log",
            iface: "lo",
            binary: false,
            filter: ["udp", "port", "1090"],
            maxBytes: PLAN.metadata_max_bytes,
          });
          owned.push(c.name);
          captures.push(c);
          await c.ready();
        }
        const snapshot = async (label, full = true) => {
          const [clients, servers] = await Promise.all([
            Promise.all(
              [1, 2].map((n) => admin(nativeName, 2190 + n, "GET", "/state")),
            ),
            Promise.all(
              [1, 2].map((n) =>
                admin("bb-g01-entry" + n + "-shim", 2291, "GET", "/state"),
              ),
            ),
          ]);
          const row = {
            label,
            utc: new Date().toISOString(),
            clients,
            servers,
          };
          if (full)
            row.udp_socket_inventory = await Promise.all(
              [1, 2].map((n) =>
                exec(
                  [
                    "docker",
                    "exec",
                    "bb-g01-entry" + n + "-shim",
                    "ss",
                    "-uan",
                  ],
                  { allowFailure: true, timeout: 3000 },
                ),
              ),
            );
          if (!full)
            for (const part of [...row.clients, ...row.servers])
              if (part.data)
                for (const key of [
                  "udp_inputs",
                  "packet_events",
                  "observations",
                  "full_observations",
                ])
                  delete part.data[key];
          fs.appendFileSync(
            path.join(dir, full ? "snapshots.jsonl" : "counters.jsonl"),
            JSON.stringify(row) + "\n",
          );
          return row;
        };
        const fetch = async (phase, index, size, timeout) => {
          const started = new Date().toISOString(),
            p = await exec(
              [
                "docker",
                "exec",
                nativeName,
                "/prep/bin/probe",
                "fetch",
                PLAN.endpoint,
                String(size),
                String(timeout),
              ],
              { allowFailure: true, timeout: timeout + 4000 },
            );
          let data;
          try {
            data = JSON.parse(p.stdout);
          } catch {
            data = { ok: false, process: p };
          }
          const row = {
            phase,
            index,
            requested_bytes: size,
            scheduled_started: started,
            ...data,
          };
          fs.appendFileSync(
            path.join(dir, "proofs.jsonl"),
            JSON.stringify(row) + "\n",
          );
          return row;
        };
        await snapshot("before-native");
        fs.writeFileSync(path.join(dir, "start-native"), "go\n");
        const startup = performance.now();
        for (let i = 0; i < 3; i++)
          record.warmup.push(
            await at(startup, PLAN.warmup_start_ms[i], () =>
              fetch("warmup", i, 4096, PLAN.warmup_timeout_ms),
            ),
          );
        record.last_warmup_ok = Boolean(record.warmup.at(-1)?.ok);
        record.own_warmup_conclusive = record.last_warmup_ok;
        record.pid_before = (
          await exec(
            [
              "docker",
              "exec",
              nativeName,
              "sh",
              "-c",
              "cat /group/adapter1.pid /group/adapter2.pid; cat /proc/1/stat",
            ],
            { allowFailure: true },
          )
        ).stdout;
        await snapshot("phase-start");
        const start = performance.now(),
          phaseUTC = new Date();
        record.phase_started = phaseUTC.toISOString();
        record.phase_started_unix_micros = phaseUTC.getTime() * 1000;
        record.phase_finished = new Date(
          phaseUTC.getTime() + PLAN.phase_ms,
        ).toISOString();
        record.phase_finished_unix_micros =
          (phaseUTC.getTime() + PLAN.phase_ms) * 1000;
        record.measurement_window = {
          start_inclusive: record.phase_started,
          end_exclusive: record.phase_finished,
          pcap_warmup_is_not_phase_anchor: true,
        };
        const jobs = PLAN.phase_fetch_start_ms.map((ms, i) =>
          at(start, ms, async () => {
            const r = await fetch(
              "phase",
              i,
              PLAN.proof_sizes[i % 2],
              PLAN.phase_fetch_timeout_ms,
            );
            record.proofs.push(r);
          }),
        );
        jobs.push(at(start, 9500, () => snapshot("pre-reset")));
        jobs.push(
          at(start, PLAN.interruption_start_ms, async () => {
            const row = {
              requested_at: new Date().toISOString(),
              mode: group.kind,
            };
            record.interruption = row;
            let rotation;
            if (group.kind === "framed")
              await exec(["docker", "stop", "--time", "1", coreName]);
            else
              await exec([
                "docker",
                "exec",
                nativeName,
                "iptables",
                "-I",
                "OUTPUT",
                "1",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "DROP",
              ]);
            row.interruption_began = new Date().toISOString();
            const stopAt = performance.now();
            if (group.kind === "v2") {
              const profile = JSON.parse(
                fs.readFileSync(
                  path.join(prep.directory, "public/v2-profile.json"),
                ),
              );
              rotation = Promise.all(
                [1, 2].map((n) =>
                  admin(nativeName, 2190 + n, "POST", "/epoch", {
                    id: group.id + "-reset",
                    group_id: group.id,
                    split: group.split,
                    class: "belnet",
                    profile,
                  }),
                ),
              );
            }
            await delay(PLAN.interruption_ms - since(stopAt));
            if (group.kind === "framed")
              await exec(["docker", "start", coreName]);
            else
              await exec([
                "docker",
                "exec",
                nativeName,
                "iptables",
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "DROP",
              ]);
            row.interruption_ended = new Date().toISOString();
            if (rotation) row.rotation = await rotation;
            await snapshot("post-reset");
          }),
        );
        jobs.push(
          (async () => {
            for (let ms = 0; ms <= PLAN.phase_ms; ms += 1000) {
              if (since(start) > ms + 750) {
                fs.appendFileSync(
                  path.join(dir, "counters.jsonl"),
                  JSON.stringify({
                    label: "counter-" + ms,
                    missed: true,
                    utc: new Date().toISOString(),
                  }) + "\n",
                );
                continue;
              }
              await at(start, ms, () => snapshot("counter-" + ms, false));
            }
          })(),
        );
        jobs.push(at(start, 42000, () => snapshot("idle-start")));
        await at(start, PLAN.phase_ms, async () => {
          record.phase_deadline_callback_at = new Date().toISOString();
        });
        await Promise.allSettled(jobs).then((results) => {
          for (const r of results)
            if (r.status === "rejected") record.errors.push(String(r.reason));
        });
        await snapshot("phase-end");
        record.pid_after = (
          await exec(
            [
              "docker",
              "exec",
              nativeName,
              "sh",
              "-c",
              "cat /group/adapter1.pid /group/adapter2.pid; cat /proc/1/stat",
            ],
            { allowFailure: true },
          )
        ).stdout;
        record.iptables = await exec(
          ["docker", "exec", nativeName, "iptables-save"],
          { allowFailure: true },
        );
        const ended = Date.parse(record.interruption?.interruption_ended || "");
        const successful = record.proofs
          .filter((p) => p.ok && Date.parse(p.started) >= ended)
          .sort((a, b) => Date.parse(a.finished) - Date.parse(b.finished));
        record.straddling_successes = record.proofs.filter(
          (p) =>
            p.ok &&
            Date.parse(p.started) < ended &&
            Date.parse(p.finished) >= ended,
        );
        record.first_post_reset_success = successful[0] || null;
        record.recovery_ms = successful.length
          ? Date.parse(successful[0].finished) - ended
          : null;
        record.recovery_gate_met =
          record.own_warmup_conclusive &&
          record.recovery_ms !== null &&
          record.recovery_ms <= PLAN.recovery_gate_ms;
        record.phase_proofs = record.proofs.sort((a, b) => a.index - b.index);
        finished = true;
      } catch (error) {
        record.errors.push(String(error));
      } finally {
        for (const c of captures) {
          await c.stop().catch((e) => record.errors.push(String(e)));
        }
        record.captures = captures.map((c) => c.result());
        record.finished = new Date().toISOString();
        record.completed_schedule = finished;
        save(path.join(dir, "result.json"), record);
        trials.push(record);
        save(path.join(output, "trials.json"), trials);
        await archiveRemove(owned, dir);
      }
      console.log(
        JSON.stringify({
          group: group.id,
          warmup: record.warmup.map((p) => p.ok),
          proof_ok: record.proofs.filter((p) => p.ok).length,
          recovery_ms: record.recovery_ms,
          errors: record.errors,
        }),
      );
    }
    save(path.join(output, "status.json"), {
      status: "complete_engineering_checkpoint",
      groups: trials.length,
      last_v2_warmup_success: Boolean(
        trials.filter((t) => t.group.kind === "v2").at(-1)?.last_warmup_ok,
      ),
      app_result_scope:
        "If last v2 baseline warmup failed, comparative application results are inconclusive; no statistical/DPI success implied",
      dpi_collection_authorized: false,
    });
  } finally {
    await archiveRemove(globalCreated, output);
  }
}
if (require.main === module)
  main().catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
module.exports = { validateFreeze, main };

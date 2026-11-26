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
const { vmClock, phaseWindow, recovery } = require("./clock.cjs");
const delay = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
const since = (start) => performance.now() - start;
async function at(start, ms, fn) {
  await delay(ms - since(start));
  return fn();
}
function validateFreeze(file) {
  const freeze = JSON.parse(fs.readFileSync(file));
  if (
    freeze.schema !== "belnet-g02-stage-a2/v1" ||
    freeze.stage !== "A2" ||
    !freeze.frozen_at ||
    !/^[-a-z0-9]{1,40}$/.test(freeze.run_id || "")
  )
    throw Error("Invalid frozen stage-A manifest");
  if (
    freeze.protocol_sha256 !==
      hash(path.join(ROOT, "lab/dpi-g02/PROTOCOL.md")) ||
    freeze.plan_sha256 !== hash(path.join(__dirname, "plan.json"))
  )
    throw Error("Protocol or finite plan changed after freeze");
  if (JSON.stringify(freeze.plan) !== JSON.stringify(PLAN))
    throw Error("Embedded finite plan mismatch");
  const sources = sourceHashes();
  if (
    JSON.stringify(Object.keys(sources).sort()) !==
    JSON.stringify(Object.keys(freeze.source_sha256 || {}).sort())
  )
    throw Error("Frozen source set differs");
  for (const [file, h] of Object.entries(sources))
    if (freeze.source_sha256[file] !== h)
      throw Error("Source changed: " + file);
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
  const output = path.join(ROOT, "lab/dpi-g02/run/stage-a2-" + freeze.run_id);
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
    .filter((n) => n.startsWith("bb-g02-"));
  if (existing.length)
    throw Error(
      "Existing bb-g02 containers must be reviewed, not overwritten: " +
        existing.join(","),
    );
  const runningOld = (
    await exec(["docker", "ps", "--format", "{{.Names}}"])
  ).stdout
    .split("\n")
    .filter((name) => name.startsWith("bb-g01-"));
  if (runningOld.length)
    throw Error("G01 is still running; A2 will not touch its containers");
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
  const clock = async (container, label) => {
    const before = new Date(),
      host_before = before.toISOString();
    const result = await exec(
      ["docker", "exec", container, "/prep/bin/probe", "clock"],
      { timeout: 4000 },
    );
    const sample = vmClock(JSON.parse(result.stdout)),
      after = new Date();
    return {
      ...sample,
      label,
      host_before,
      host_after: after.toISOString(),
      vm_minus_host_offset_bounds_micros: {
        lower: sample.unix_micros - after.getTime() * 1000 - 1000,
        upper: sample.unix_micros - before.getTime() * 1000 + 1000,
      },
      clock_uncertainty_micros:
        (after.getTime() - before.getTime()) * 1000 + 2000,
    };
  };
  const archiveRemove = async (names, dir) => {
    for (const name of [...names].reverse()) {
      const logs = await exec(["docker", "logs", name], { allowFailure: true });
      fs.writeFileSync(
        path.join(dir, name + ".log"),
        logs.stdout + logs.stderr,
      );
      if (name === "bb-g02-service-helper")
        fs.writeFileSync(
          path.join(dir, "service.log"),
          logs.stdout + logs.stderr,
        );
      await exec(["docker", "rm", "-f", name], { allowFailure: true });
    }
  };
  try {
    await create(
      "bb-g02-service-helper",
      ["--network", "container:bb-lab-service-1"],
      "exec /prep/bin/probe serve",
      globalCreated,
    );
    for (let n = 1; n <= 2; n++) {
      const network = ["--network", "container:bb-lab-entry" + n + "-1"];
      await create(
        "bb-g02-entry" + n + "-shim",
        network,
        "BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN; exec /bridge udp-stream-server -listen 127.0.0.1:21990 -target 10.88.0.1" +
          n +
          ":1090 -lab-control 127.0.0.1:2291",
        globalCreated,
      );
      await create(
        "bb-g02-entry" + n + "-core",
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
      const nativeName = "bb-g02-" + freeze.run_id + "-" + group.id,
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
            "G02_KIND=" + group.kind,
            "-e",
            "G02_MAX_QUEUE_AGE=" + group.max_queue_age,
          ],
          "exec /bin/sh /lab/dpi-g02/runtime/client.sh",
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
                admin("bb-g02-entry" + n + "-shim", 2291, "GET", "/state"),
              ),
            ),
          ]);
          const row = {
            label,
            host_utc: new Date().toISOString(),
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
                    "bb-g02-entry" + n + "-shim",
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
                  "expired_events",
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
            host_scheduled_started: started,
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
        const phaseClock = await clock(nativeName, "phase-start");
        Object.assign(record, phaseWindow(phaseClock, PLAN.phase_ms));
        record.phase_clock = phaseClock;
        record.clock_scope =
          "VM unix_microsecond proof/packet/phase/edge clocks; host monotonic clock schedules only";
        record.measurement_window = {
          start_inclusive_unix_micros: record.phase_started_unix_micros,
          end_exclusive_unix_micros: record.phase_finished_unix_micros,
          clock: "linux-vm",
          pcap_warmup_is_not_phase_anchor: true,
        };
        const start = performance.now();
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
              host_requested_at: new Date().toISOString(),
              mode: group.kind,
              variant: group.variant,
            };
            record.interruption = row;
            row.vm_before_stop = await clock(nativeName, "before-core-stop");
            await exec(["docker", "stop", "--time", "1", coreName]);
            row.vm_after_stop = await clock(nativeName, "after-core-stop");
            row.interruption_began = row.vm_after_stop.utc;
            row.interruption_began_unix_micros = row.vm_after_stop.unix_micros;
            await delay(PLAN.interruption_ms);
            row.vm_before_start = await clock(nativeName, "before-core-start");
            await exec(["docker", "start", coreName]);
            row.vm_after_start = await clock(nativeName, "after-core-start");
            row.interruption_ended = row.vm_after_start.utc;
            row.interruption_ended_unix_micros = row.vm_after_start.unix_micros;
            row.absence_bracket_micros = {
              lower:
                row.vm_before_start.unix_micros - row.vm_after_stop.unix_micros,
              upper:
                row.vm_after_start.unix_micros - row.vm_before_stop.unix_micros,
            };
            row.edge_scope =
              "Actual stop/start lie in before/after VM sample brackets. Strict post uses after-start; edge-overlap packets/proofs remain straddling.";
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
                    host_utc: new Date().toISOString(),
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
          record.phase_end_clock = await clock(nativeName, "phase-end");
          record.phase_deadline_callback_at = record.phase_end_clock.utc;
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
        const recovered = recovery(
          record.proofs,
          record.interruption?.interruption_ended_unix_micros,
        );
        record.straddling_successes = recovered.straddling;
        record.first_post_reset_success = recovered.first;
        record.recovery_micros = recovered.recovery_micros;
        record.recovery_ms =
          recovered.recovery_micros === null
            ? null
            : recovered.recovery_micros / 1000;
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
      last_retain_warmup_success: Boolean(
        trials.filter((t) => t.group.max_queue_age === "0").at(-1)
          ?.last_warmup_ok,
      ),
      app_result_scope:
        "If last retain control warmup failed, comparative application results are inconclusive; no statistical/DPI success implied",
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

"use strict";
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process"),
  crypto = require("crypto");
const {
  ROOT,
  args,
  exec,
  save,
  hash,
  idOf,
  proxyConfig,
  coreConfigs,
} = require("./common.cjs");
const { validate } = require("./freeze.cjs");
const { tooling } = require("./tools.cjs");
const { Capture } = require("./capture.cjs");
const { makeIndex } = require("./quality.cjs");
const wait = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms))),
  q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
const ENDPOINT = "f3839udf9nsefrp3ug8zotg37jh6zcwejrps6hmdt4xstrpfupdy.bdx";
async function main() {
  const a = args(process.argv.slice(2));
  if (!a.freeze) throw Error("Frozen manifest required");
  const checked = validate(path.resolve(a.freeze)),
    { freeze: f, prep } = checked;
  if (a["validate-only"] === "true") {
    console.log(JSON.stringify({ valid: true, groups: f.groups.length }));
    return;
  }
  const out = path.resolve(a.output || "lab/dpi-g03/run/" + f.run_id);
  if (fs.existsSync(out))
    throw Error("Refusing overwrite / attempt resampling");
  fs.mkdirSync(out, { recursive: true });
  save(path.join(out, "run-start.json"), checked);
  let stopRequested = false;
  const requestStop = () => {
    stopRequested = true;
  };
  process.once("SIGTERM", requestStop);
  process.once("SIGINT", requestStop);
  const owns = [],
    groups = [],
    rollback = [],
    image = prep.runtime_image;
  const binds = [
    "-v",
    prep.directory + ":/prep:ro",
    "-v",
    prep.adapter.path + ":/bridge:ro",
    "-v",
    path.join(ROOT, "lab") + ":/lab",
  ];
  async function create(name, opts, cmd, list = owns) {
    const exists = await exec(
      ["docker", "inspect", "--type", "container", name],
      { allowFailure: true },
    );
    if (exists.code === 0)
      throw Error("Container name already exists; refusing ownership: " + name);
    list.push(name);
    await exec([
      "docker",
      "run",
      "-d",
      "--name",
      name,
      ...opts,
      ...binds,
      "--entrypoint",
      "/bin/sh",
      image,
      "-c",
      cmd,
    ]);
  }
  async function remove(names, dir) {
    for (const n of [...names].reverse()) {
      if (!/-capture$|-udp[12]$|-leak$/.test(n)) {
        const l = await exec(["docker", "logs", n], { allowFailure: true });
        fs.writeFileSync(path.join(dir, n + ".log"), l.stdout + l.stderr);
      }
      await exec(["docker", "rm", "-f", n], { allowFailure: true });
    }
  }
  async function clock(name) {
    const r = await exec(["docker", "exec", name, "/prep/bin/probe", "clock"]);
    return JSON.parse(r.stdout);
  }
  const entries = JSON.parse(
    fs.readFileSync(path.join(prep.directory, "private/credentials.json")),
  );
  const cert = new crypto.X509Certificate(
      fs.readFileSync(path.join(prep.directory, "private/tls/cert.pem")),
    ),
    spki = crypto
      .createHash("sha256")
      .update(cert.publicKey.export({ type: "spki", format: "der" }))
      .digest("base64");
  let infrastructure = false;
  try {
    // Archive the exact task-owned Go443 process before replacing only this listener.
    for (let n = 1; n <= 2; n++) {
      const name = "bb-lab-entry" + n + "-1";
      const r = await exec([
        "docker",
        "exec",
        name,
        "sh",
        "-c",
        "for p in /proc/[0-9]*; do [ -r \"$p/cmdline\" ] || continue; tr '\\000' ' ' <\"$p/cmdline\" | grep -q '^/lab/dpi-v2/bin/belnet-bridge udp-server -listen :443 ' && { basename \"$p\"; break; }; done",
      ]);
      const pid = r.stdout.trim();
      if (!/^\d+$/.test(pid))
        throw Error("Expected known old Go443 server missing " + name);
      const meta = await exec([
        "docker",
        "exec",
        name,
        "sh",
        "-c",
        "cat /proc/" +
          pid +
          "/stat; sha256sum /proc/" +
          pid +
          '/exe; tr "\\000" "\\n" </proc/' +
          pid +
          "/cmdline",
      ]);
      const oldArgs = (
        await exec(["docker", "exec", name, "cat", "/proc/" + pid + "/cmdline"])
      ).stdout
        .split("\0")
        .filter(Boolean);
      const oldEnv = (
        await exec(["docker", "exec", name, "cat", "/proc/" + pid + "/environ"])
      ).stdout
        .split("\0")
        .filter(Boolean);
      const cwd = (
        await exec([
          "docker",
          "exec",
          name,
          "readlink",
          "/proc/" + pid + "/cwd",
        ])
      ).stdout.trim();
      const privateDir = path.join(out, "private");
      fs.mkdirSync(privateDir, { recursive: true });
      save(path.join(privateDir, "entry" + n + "-process.json"), {
        argv: oldArgs,
        environment: oldEnv,
        cwd,
      });
      const script = path.join(privateDir, "restore-entry" + n + ".sh");
      fs.writeFileSync(
        script,
        "#!/bin/sh\nset -eu\ncd " +
          q(cwd) +
          "\necho $$ > " +
          q("/lab/" + path.relative(path.join(ROOT, "lab"), script + ".pid")) +
          "\nexec env -i " +
          oldEnv.map(q).join(" ") +
          " " +
          oldArgs.map(q).join(" ") +
          "\n",
        { mode: 0o700 },
      );
      save(path.join(out, "entry" + n + "-old443.json"), {
        name,
        pid,
        metadata: meta,
        argv: oldArgs,
        environment_names: oldEnv.map((v) => v.slice(0, v.indexOf("="))),
        environment_archive_sha256: hash(
          path.join(privateDir, "entry" + n + "-process.json"),
        ),
        rollback_script_sha256: hash(script),
      });
      rollback.push({ name, n, script, argv: oldArgs, environment: oldEnv });
      await exec(["docker", "exec", name, "kill", "-TERM", pid]);
    }
    await create(
      "bb-g03-service",
      ["--network", "container:bb-lab-service-1"],
      "exec /prep/bin/bench-server -listen 0.0.0.0:8083 -native-plain -role native-application",
    );
    const configs = coreConfigs(entries, "10.88.0.60");
    for (let n = 1; n <= 2; n++) {
      const network = ["--network", "container:bb-lab-entry" + n + "-1"];
      await create(
        "bb-g03-entry" + n + "-shim",
        network,
        "BRIDGE_TOKEN=$(cat /prep/private/bridge-token); export BRIDGE_TOKEN; exec /bridge udp-stream-server -listen 127.0.0.1:21990 -target 10.88.0.1" +
          n +
          ":1090 -lab-control 127.0.0.1:2291",
      );
      await create(
        "bb-g03-entry" + n + "-tls",
        network,
        "exec /prep/bin/bench-server -listen 127.0.0.1:18444 -cert /prep/private/tls/cert.pem -key /prep/private/tls/key.pem -role primary-benign",
      );
      await create(
        "bb-g03-entry" + n + "-core",
        [...network, "-v", prep.sing_box.directory + ":/mature:ro"],
        "exec /mature/sing-box run -c /prep/private/entry" + n + ".json",
      );
    }
    const infrastructureChecks = [];
    for (let n = 1; n <= 2; n++) {
      const r = await exec([
        "docker",
        "exec",
        "bb-g03-entry" + n + "-core",
        "ss",
        "-ltnp",
      ]);
      for (const port of [443, 18444, 21990])
        if (!new RegExp(":" + port + "\\s").test(r.stdout))
          throw Error("Infrastructure listener missing: " + n + "/" + port);
      infrastructureChecks.push({ entry: n, listeners: r });
    }
    save(path.join(out, "infrastructure-checks.json"), infrastructureChecks);
    infrastructure = true;
    async function runGroup(g, slot) {
      const id = idOf(g),
        dir = path.join(out, id),
        names = [],
        caps = [];
      fs.mkdirSync(dir);
      save(path.join(dir, "assignment.json"), g);
      const prefix = "bb-g03-" + id,
        proxy = prefix + "-proxy",
        native = prefix + "-native",
        ip = "10.88.0." + (60 + slot),
        nativeIP = "10.88.0." + (42 + slot),
        port = 28080 + slot;
      const rec = {
        group: g,
        started_utc: new Date().toISOString(),
        errors: [],
        workloads: [],
        captures: [],
        snapshots: [],
      };
      let browser = null,
        browserDone = null;
      const nativeGroup = g.class === "belnet" || g.transport === "reality";
      const stack = g.client_stack || g.stack || "",
        isBrowser =
          /chrome|browser/i.test(stack) || g.workload_mode === "public80";
      const family = g.family || g.workload_family || g.profile,
        seed = Number(g.seed_int),
        nonce = g.nonce;
      try {
        if (
          !Number.isSafeInteger(seed) ||
          seed < 1 ||
          !/[a-f0-9]{64}/.test(nonce || "")
        )
          throw Error("Frozen bounded seed/nonce required");
        const pc = proxyConfig(g);
        save(path.join(dir, "proxy.json"), pc);
        await create(
          proxy,
          [
            "--network",
            "bb-lab_private",
            "--ip",
            ip,
            "-p",
            "127.0.0.1:" + port + ":8080",
            "-v",
            dir + ":/group",
          ],
          "exec /prep/bin/connect-proxy -listen 0.0.0.0:8080 -config /group/proxy.json -control 127.0.0.1:8091",
          names,
        );
        // Public egress uses Docker default bridge; private entries remain on bb-lab_private.
        await exec(["docker", "network", "connect", "bridge", proxy]);
        rec.proxy_route = await exec([
          "docker",
          "exec",
          proxy,
          "ip",
          "route",
          "get",
          "1.1.1.1",
        ]);
        if (nativeGroup) {
          save(path.join(dir, "client.json"), coreConfigs(entries, ip).client);
          await create(
            native,
            [
              "--network",
              "bb-lab_private",
              "--ip",
              nativeIP,
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
              ].flatMap((s) => ["--sysctl", "net.ipv4.conf." + s]),
              "-v",
              dir + ":/group",
              "-e",
              "G03_CLIENT_IP=" + nativeIP,
            ],
            "exec /bin/sh /lab/dpi-g03/runtime-v4/native-client.sh",
            names,
          );
          await create(
            prefix + "-core",
            [
              "--network",
              "container:" + native,
              "-v",
              dir + ":/group:ro",
              "-v",
              prep.sing_box.directory + ":/mature:ro",
            ],
            "exec /mature/sing-box run -c /group/client.json",
            names,
          );
        }
        rec.capture_start = await clock(proxy);
        const capture = new Capture({
          captureMode: f.capture_mode,
          bufferKiB: f.capture_buffer_kib,
          name: prefix + "-capture",
          network: proxy,
          image,
          directory: dir,
          file: "outer.pcap",
          iface: "any",
          filter: ["tcp", "port", "443"],
          maxBytes: f.pcap_cap_bytes,
        });
        names.push(capture.name);
        caps.push(capture);
        await capture.ready();
        if (nativeGroup)
          for (let n = 1; n <= 2; n++) {
            const c = new Capture({
              captureMode: f.capture_mode,
              bufferKiB: f.capture_buffer_kib,
              name: prefix + "-udp" + n,
              network: "bb-lab-entry" + n + "-1",
              image,
              directory: dir,
              file: "entry" + n + "-udp.log",
              iface: "lo",
              filter: ["udp", "port", "1090"],
              binary: false,
              maxBytes: 33554432,
            });
            names.push(c.name);
            caps.push(c);
            await c.ready();
          }
        if (nativeGroup) {
          const leak = new Capture({
            captureMode: f.capture_mode,
            bufferKiB: f.capture_buffer_kib,
            name: prefix + "-leak",
            network: native,
            image,
            directory: dir,
            file: "native-raw-udp.pcap",
            iface: "eth0",
            filter: ["udp", "port", "1090"],
            maxBytes: 8388608,
          });
          names.push(leak.name);
          caps.push(leak);
          await leak.ready();
        }
        const duration = g.workload_duration_seconds,
          scenario =
            g.workload_mode === "public80"
              ? "public"
              : g.workload_mode === "long80"
                ? "long"
                : "matched";
        const endpoint = nativeGroup
          ? "ws://" + ENDPOINT + ":8083/ws"
          : "wss://entry" + (g.entry_index || 1) + ".test/ws";
        const url =
          g.url ||
          "https://entry" +
            (g.entry_index || 1) +
            ".test/bench?family=" +
            encodeURIComponent(family) +
            "&seed=" +
            seed.toString(16).padStart(16, "0") +
            "&duration_ms=" +
            duration * 1000 +
            "&nonce=" +
            nonce;
        if (isBrowser && !nativeGroup) {
          const bd = path.join(dir, "browser");
          fs.mkdirSync(bd);
          const startfile = path.join(dir, "start-browser");
          browser = cp.spawn(
            process.execPath,
            [
              path.join(__dirname, "browser.cjs"),
              url,
              bd,
              "80",
              "http://127.0.0.1:" + port,
              g.url ? "" : spki,
              scenario,
            ],
            {
              env: {
                ...process.env,
                G03_START_FILE: startfile,
                G03_WARMUP_NONCES: JSON.stringify(g.warmup_nonces),
                G03_INITIAL_NONCE: g.initial_nonce,
              },
              stdio: ["ignore", "pipe", "pipe"],
            },
          );
          let so = "",
            se = "";
          browser.stdout.on("data", (b) => (so += b));
          browser.stderr.on("data", (b) => (se += b));
          browserDone = new Promise((resolve) =>
            browser.once("close", (code, signal) => {
              fs.writeFileSync(path.join(bd, "process.log"), so + se);
              resolve({ code, signal });
            }),
          );
          for (
            let i = 0;
            i < 150 && !fs.existsSync(path.join(bd, "ready.json"));
            i++
          )
            await wait(100);
          if (!fs.existsSync(path.join(bd, "ready.json")))
            throw Error("Browser barrier not ready");
        }
        const start = await clock(proxy);
        rec.measurement_start = start;
        const t = performance.now();
        if (nativeGroup)
          fs.writeFileSync(path.join(dir, "start-native"), "start\n");
        if (browser)
          fs.writeFileSync(path.join(dir, "start-browser"), "start\n");
        const at = async (ms, fn) => {
          await wait(ms - (performance.now() - t));
          return fn();
        };
        const runBench = async (fam, s, seconds, n, label) => {
          const cmd = [
            "docker",
            "exec",
            nativeGroup ? native : proxy,
            "/prep/bin/bench-client",
            "-mode",
            nativeGroup ? "native" : "ordinary",
            "-url",
            endpoint,
            "-family",
            fam,
            "-seed",
            String(s),
            "-duration",
            seconds + "s",
            "-nonce",
            n,
          ];
          if (nativeGroup) cmd.push("-dns", "127.3.2.1:53");
          else cmd.push("-proxy", "http://127.0.0.1:8080", "-spki", spki);
          const r = await exec(cmd, {
            allowFailure: true,
            timeout: (seconds + 12) * 1000,
          });
          let data;
          try {
            data = JSON.parse(r.stdout);
          } catch {
            data = { parse_error: true, stdout: r.stdout };
          }
          rec.workloads.push({ label, ...r, data });
          save(path.join(dir, "partial.json"), rec);
        };
        const snapshot = async (label) => {
          if (!nativeGroup) return;
          const row = {
            label,
            clock: await clock(proxy),
            clients: [],
            servers: [],
            native_process: await exec(
              [
                "docker",
                "exec",
                native,
                "sh",
                "-c",
                'cat /proc/1/stat; readlink /proc/1/exe; for f in /group/adapter?.pid; do p=$(cat "$f"); cat /proc/$p/stat; done',
              ],
              { allowFailure: true },
            ),
          };
          for (let n = 1; n <= 2; n++)
            for (const [kind, name, p] of [
              ["clients", native, 2190 + n],
              ["servers", "bb-g03-entry" + n + "-shim", 2291],
            ]) {
              const r = await exec(
                [
                  "docker",
                  "exec",
                  name,
                  "/prep/bin/probe",
                  "admin",
                  "GET",
                  "http://127.0.0.1:" + p + "/state",
                ],
                { allowFailure: true },
              );
              try {
                row[kind].push(JSON.parse(r.stdout));
              } catch {
                row[kind].push({ error: r.stderr });
              }
            }
          row.native_firewall = await exec(
            ["docker", "exec", native, "iptables-save", "-c"],
            { allowFailure: true },
          );
          row.snapshot_finished = await clock(proxy);
          rec.snapshots.push(row);
        };
        const jobs = [];
        if (!browser) {
          if (scenario === "long" && !nativeGroup)
            jobs.push(runBench(family, seed, 80, nonce, "long"));
          else {
            jobs.push(
              runBench(
                "rpc",
                ((seed - 1 + 8999) % (2 ** 48 - 1)) + 1,
                1,
                g.initial_nonce,
                "initial",
              ),
            );
            for (let i = 0; i < 3; i++)
              jobs.push(
                at([5000, 15000, 25000][i], () =>
                  runBench(
                    "rpc",
                    ((seed - 1 + 9000 + i) % (2 ** 48 - 1)) + 1,
                    1,
                    g.warmup_nonces[i],
                    "warmup-" + i,
                  ),
                ),
              );
            jobs.push(
              at(35000, () => runBench(family, seed, 45, nonce, "main")),
            );
          }
        }
        if (nativeGroup)
          for (const ms of f.native_snapshot_ms)
            jobs.push(at(ms, () => snapshot("t" + ms)));
        await at(82000, async () => {});
        rec.measurement_end = await clock(proxy);
        const quiesce = await exec(
          [
            "docker",
            "exec",
            proxy,
            "/prep/bin/probe",
            "admin",
            "POST",
            "http://127.0.0.1:8091/quiesce",
          ],
          { allowFailure: true, timeout: 5000 },
        );
        try {
          rec.quiesce = {
            ...JSON.parse(quiesce.stdout),
            process_code: quiesce.code,
          };
        } catch {
          rec.quiesce = {
            process_code: quiesce.code,
            error: "invalid quiesce JSON",
          };
        }
        await wait(f.minimum_drain_ms);
        rec.capture_drain = await capture.drain({
          budgetMS: f.stats_drain_budget_ms,
          stableMS: f.stats_stable_ms,
        });
        rec.drain_end = await clock(proxy);
        for (const c of caps) {
          await c.stop();
          rec.captures.push(c.result());
        }
        rec.capture_end = await clock(proxy);
        await Promise.all(jobs);
        if (browserDone)
          rec.browser = await Promise.race([
            browserDone,
            wait(10000).then(() => ({ timeout: true })),
          ]);
        if (browser) {
          for (const [key, file] of [["browser_teardown", "teardown.json"]])
            try {
              rec[key] = JSON.parse(
                fs.readFileSync(path.join(dir, "browser", file)),
              );
            } catch {}
          rec.browser_acquisition_complete =
            fs.existsSync(path.join(dir, "browser/private/session-raw.json")) &&
            fs.existsSync(path.join(dir, "browser/session.json")) &&
            !fs.existsSync(path.join(dir, "browser/failure.json"));
        }
        const metadata = {
          group_id: id,
          split: g.split,
          class: g.class,
          profile: g.profile || family,
          server_ports: [443],
          capture_started_utc: rec.capture_start.utc,
          capture_ended_utc: rec.capture_end.utc,
          measurement_start_unix_micros: start.unix_micros,
          measured_seconds: 80,
          prefix_grace_seconds: 2,
          window_offsets_seconds: f.window_offsets_seconds,
          freeze_sha256: checked.freeze_sha256,
          capture_cap_hit: capture.capped,
          packets_dropped: capture.result().dropped_by_kernel,
          capture_cap_bytes: f.pcap_cap_bytes,
        };
        save(path.join(dir, "observer-meta.json"), metadata);
        const tool = tooling({ observationOnly: f.stage === "Q" });
        rec.observer_process = await exec(
          [
            tool.observer.path,
            "-pcap",
            path.join(dir, "outer.pcap"),
            "-meta",
            path.join(dir, "observer-meta.json"),
            "-out",
            path.join(dir, "windows.json"),
          ],
          { allowFailure: true, timeout: 60000 },
        );
        rec.longflow_process = await exec(
          [
            tool.longflow.path,
            "-pcap",
            path.join(dir, "outer.pcap"),
            "-meta",
            path.join(dir, "observer-meta.json"),
            "-out",
            path.join(dir, "longflow.json"),
          ],
          { allowFailure: true, timeout: 60000 },
        );
      } catch (e) {
        rec.errors.push(e.stack);
      } finally {
        if (browser) browser.kill("SIGTERM");
        for (const c of caps) {
          await c.stop();
          if (!rec.captures.some((x) => x.name === c.name))
            rec.captures.push(c.result());
        }
        await remove(names, dir);
        rec.finished_utc = new Date().toISOString();
        save(path.join(dir, "result.json"), rec);
        groups.push(rec);
        save(
          path.join(out, "observer-index.json"),
          makeIndex(
            groups,
            (id) => {
              try {
                return JSON.parse(
                  fs.readFileSync(path.join(out, id, "windows.json")),
                );
              } catch {
                return null;
              }
            },
            f.stage,
          ),
        );
        save(path.join(out, "status.json"), {
          stage: f.stage,
          complete: groups.length,
          total: f.groups.length,
          groups: groups.map((x) => ({ id: idOf(x.group), errors: x.errors })),
        });
      }
    }
    // Bounded distinct slot cohorts; no repeats or replacement of failed attempts.
    for (const batch of f.batches) {
      if (stopRequested || fs.existsSync(path.join(out, "STOP_AFTER_BATCH")))
        break;
      await Promise.all(
        batch.map((id, slot) =>
          runGroup(
            f.groups.find((g) => g.group_id === id),
            slot,
          ),
        ),
      );
    }
  } finally {
    await remove(owns, out);
    const restorations = [];
    for (const r of rollback) {
      const script = "/lab/" + path.relative(path.join(ROOT, "lab"), r.script);
      const launched = await exec(
        ["docker", "exec", "-d", r.name, "/bin/sh", script],
        { allowFailure: true },
      );
      await wait(400);
      const pidResult = await exec(
        ["docker", "exec", r.name, "cat", script + ".pid"],
        { allowFailure: true },
      );
      const pid = pidResult.stdout.trim();
      let verification = { code: -1, stdout: "invalid restored pid" },
        envMatches = false,
        argsMatch = false;
      if (/^\d+$/.test(pid)) {
        verification = await exec(["docker", "exec", r.name, "ss", "-ltnp"], {
          allowFailure: true,
        });
        const restoredArgs = await exec(
          ["docker", "exec", r.name, "cat", "/proc/" + pid + "/cmdline"],
          { allowFailure: true },
        );
        argsMatch =
          JSON.stringify(restoredArgs.stdout.split("\0").filter(Boolean)) ===
          JSON.stringify(r.argv);
        const restoredEnv = await exec(
          ["docker", "exec", r.name, "cat", "/proc/" + pid + "/environ"],
          { allowFailure: true },
        );
        envMatches =
          JSON.stringify(
            restoredEnv.stdout.split("\0").filter(Boolean).sort(),
          ) === JSON.stringify([...r.environment].sort());
      }
      const listenerMatches = verification.stdout
        .split("\n")
        .some(
          (line) => /:443\s/.test(line) && line.includes("pid=" + pid + ","),
        );
      const ok =
        launched.code === 0 &&
        verification.code === 0 &&
        listenerMatches &&
        argsMatch &&
        envMatches;
      restorations.push({
        name: r.name,
        pid,
        ok,
        args_match: argsMatch,
        environment_match: envMatches,
        listener_match: listenerMatches,
        launched,
        verification,
      });
    }
    save(path.join(out, "restoration.json"), {
      restorations,
      all_restored:
        restorations.length === rollback.length &&
        restorations.every((r) => r.ok),
    });
    if (restorations.some((r) => !r.ok)) process.exitCode = 2;
    save(path.join(out, "completion.json"), {
      finished_utc: new Date().toISOString(),
      infrastructure_started: infrastructure,
      stopped_after_batch:
        stopRequested || fs.existsSync(path.join(out, "STOP_AFTER_BATCH")),
      attempted: groups.length,
      total: f.groups.length,
      groups: groups.map((r) => ({ id: idOf(r.group), errors: r.errors })),
      source_hashes_unchanged: checked.freeze.files_sha256,
    });
  }
}
if (require.main === module)
  main().catch((e) => {
    console.error(e.stack);
    process.exitCode = 1;
  });
module.exports = { main };

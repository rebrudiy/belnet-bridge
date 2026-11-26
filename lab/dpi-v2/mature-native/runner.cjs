"use strict";
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process"),
  crypto = require("crypto");
const ROOT = process.cwd(),
  OUT = path.resolve("out/dpi-v2/mature-native"),
  LAB = path.resolve("lab"),
  MATURE = path.resolve("out/dpi-v2/mature/bin"),
  NATIVE = "belnet-bridge:dpi-v2",
  CLIENT = "bb-dpi-mature-client",
  created = [];
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
function save(name, data) {
  fs.mkdirSync(path.dirname(path.join(OUT, name)), { recursive: true });
  fs.writeFileSync(path.join(OUT, name), JSON.stringify(data, null, 2) + "\n");
}
function call(args, options = {}) {
  const p = cp.spawnSync(args[0], args.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    timeout: options.timeout || 45000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (p.status !== 0 && !options.allowFailure)
    throw Error(
      args.slice(0, 3).join(" ") +
        ": " +
        (p.stderr || p.error || "exit " + p.status),
    );
  return { code: p.status, stdout: p.stdout || "", stderr: p.stderr || "" };
}
function docker(...args) {
  return call(["docker", ...args]).stdout.trim();
}
function writePrivate(name, obj) {
  fs.writeFileSync(
    path.join(OUT, "private", name),
    JSON.stringify(obj, null, 2) + "\n",
    { mode: 0o600 },
  );
}
const URL =
  "http://f3839udf9nsefrp3ug8zotg37jh6zcwejrps6hmdt4xstrpfupdy.bdx:8081";
async function main() {
  if (fs.existsSync(path.join(OUT, "preregistration.json")))
    throw Error("Refusing to overwrite an existing run");
  if (fs.existsSync(path.join(LAB, "dpi-v2/run/mature-native/client")))
    throw Error("Refusing to reuse native identity");
  const plan = {
    seed: 202611191844,
    created_at: new Date().toISOString(),
    transport: "sing-box1.14.4 VLESS REALITY Vision XUDP",
    decoy:
      "private self-signed TLS1.3 on same first-node namespace; functionality only, no public camouflage claim",
    client_ip: "10.88.0.41",
    groups: Array.from({ length: 6 }, (_, i) => ({
      id: "mature-native-" + i,
      split: i < 3 ? "train" : i === 3 ? "validation" : "test",
      action: i
        ? "restart sing-box client only; retain native BelNet process"
        : "fresh native coldstart",
      proof_sizes: [4096, 16384],
    })),
    runtime_image: docker("image", "inspect", NATIVE, "--format", "{{.Id}}"),
  };
  save("preregistration.json", plan);
  fs.mkdirSync(path.join(OUT, "private"), { recursive: true });
  for (let n = 1; n <= 2; n++) {
    const keyText = docker(
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      MATURE + ":/mature:ro",
      NATIVE,
      "/mature/sing-box",
      "generate",
      "reality-keypair",
    );
    const keys = Object.fromEntries(
      keyText
        .split("\n")
        .filter((x) => x.includes(":"))
        .map((x) => {
          const [a, ...b] = x.split(":");
          return [a.toLowerCase().trim(), b.join(":").trim()];
        }),
    );
    const uuid = crypto.randomUUID(),
      short = crypto.randomBytes(4).toString("hex"),
      address = "10.88.0.1" + n;
    const server = {
      log: { level: "debug", timestamp: true },
      inbounds: [
        {
          type: "vless",
          tag: "belnet-only",
          listen: "0.0.0.0",
          listen_port: 19443,
          users: [{ name: "native-lab", uuid, flow: "xtls-rprx-vision" }],
          tls: {
            enabled: true,
            server_name: "decoy.test",
            reality: {
              enabled: true,
              handshake: { server: "127.0.0.1", server_port: 18443 },
              private_key: keys.privatekey || keys.private,
              short_id: [short],
            },
          },
        },
      ],
      outbounds: [{ type: "direct", tag: "native-first-node" }],
      route: {
        rules: [
          {
            inbound: ["belnet-only"],
            network: "udp",
            action: "route",
            override_address: address,
            override_port: 1090,
            outbound: "native-first-node",
          },
          { action: "reject" },
        ],
      },
    };
    writePrivate("entry" + n + "-server.json", server);
    const outbound = {
      type: "vless",
      tag: "entry" + n,
      server: address,
      server_port: 19443,
      uuid,
      flow: "xtls-rprx-vision",
      packet_encoding: "xudp",
      tls: {
        enabled: true,
        server_name: "decoy.test",
        utls: { enabled: true, fingerprint: "chrome" },
        reality: {
          enabled: true,
          public_key: keys.publickey || keys.public,
          short_id: short,
        },
      },
    };
    if (
      !outbound.tls.reality.public_key ||
      !server.inbounds[0].tls.reality.private_key
    )
      throw Error("Failed to parse REALITY keys");
    plan["entry" + n] = {
      address,
      port: 19443,
      native_udp_target: address + ":1090",
      public_key: outbound.tls.reality.public_key,
    };
    plan.outbounds ??= [];
    plan.outbounds.push(outbound);
    docker(
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      OUT + ":/work",
      NATIVE,
      "openssl",
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      "/work/private/entry" + n + "-decoy.key",
      "-out",
      "/work/private/entry" + n + "-decoy.crt",
      "-days",
      "1",
      "-subj",
      "/CN=decoy.test",
      "-addext",
      "subjectAltName=DNS:decoy.test",
    );
    docker(
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      OUT + ":/work",
      "-v",
      MATURE + ":/mature:ro",
      NATIVE,
      "/mature/sing-box",
      "check",
      "-c",
      "/work/private/entry" + n + "-server.json",
    );
    const name = "bb-dpi-mature-entry" + n;
    const script =
      "openssl s_server -accept 127.0.0.1:18443 -cert /work/private/entry" +
      n +
      "-decoy.crt -key /work/private/entry" +
      n +
      "-decoy.key -www -tls1_3 > /work/entry" +
      n +
      "-decoy.log 2>&1 & exec /mature/sing-box run -c /work/private/entry" +
      n +
      "-server.json";
    docker(
      "run",
      "-d",
      "--name",
      name,
      "--network",
      "container:bb-lab-entry" + n + "-1",
      "-v",
      OUT + ":/work",
      "-v",
      MATURE + ":/mature:ro",
      "--entrypoint",
      "/bin/sh",
      NATIVE,
      "-c",
      script,
    );
    created.push(name);
  }
  const client = {
    log: { level: "debug", timestamp: true },
    inbounds: [1, 2].map((n) => ({
      type: "direct",
      tag: "udp-entry" + n,
      listen: "127.0.0.1",
      listen_port: 19090 + n,
      network: "udp",
      override_address: "10.88.0.1" + n,
      override_port: 1090,
      udp_timeout: "5m",
    })),
    outbounds: plan.outbounds,
    route: {
      rules: [1, 2]
        .map((n) => ({
          inbound: ["udp-entry" + n],
          action: "route",
          outbound: "entry" + n,
        }))
        .concat([{ action: "reject" }]),
    },
  };
  writePrivate("client.json", client);
  delete plan.outbounds;
  save("preregistration.json", plan);
  docker(
    "run",
    "--rm",
    "--network",
    "none",
    "-v",
    OUT + ":/work",
    "-v",
    MATURE + ":/mature:ro",
    NATIVE,
    "/mature/sing-box",
    "check",
    "-c",
    "/work/private/client.json",
  );
  docker(
    "run",
    "-d",
    "--name",
    CLIENT,
    "--network",
    "bb-lab_private",
    "--ip",
    "10.88.0.41",
    "--cap-add",
    "NET_ADMIN",
    "--device",
    "/dev/net/tun",
    "--sysctl",
    "net.ipv4.conf.all.route_localnet=1",
    "--sysctl",
    "net.ipv4.conf.lo.route_localnet=1",
    "--sysctl",
    "net.ipv4.conf.all.accept_local=1",
    "--sysctl",
    "net.ipv4.conf.lo.accept_local=1",
    "--sysctl",
    "net.ipv4.conf.all.rp_filter=0",
    "--sysctl",
    "net.ipv4.conf.lo.rp_filter=0",
    "-v",
    LAB + ":/lab",
    "-v",
    OUT + ":/work",
    "-v",
    MATURE + ":/mature:ro",
    "--entrypoint",
    "/bin/sh",
    NATIVE,
    "/lab/dpi-v2/mature-native/client.sh",
  );
  created.push(CLIENT);
  const trials = [];
  for (let i = 0; i < plan.groups.length; i++) {
    const group = plan.groups[i],
      capture = "bb-dpi-mature-capture-" + i,
      pcap = "/work/" + group.id + ".pcap";
    docker(
      "run",
      "-d",
      "--name",
      capture,
      "--network",
      "container:" + CLIENT,
      "-v",
      OUT + ":/work",
      NATIVE,
      "tcpdump",
      "-U",
      "-i",
      "eth0",
      "-w",
      pcap,
      "tcp",
      "port",
      "19443",
      "or",
      "udp",
      "port",
      "1090",
    );
    created.push(capture);
    await delay(350);
    const row = { ...group, started: new Date().toISOString(), proofs: [] };
    if (i)
      row.rotation = call([
        "docker",
        "exec",
        CLIENT,
        "/bin/sh",
        "-c",
        'kill -TERM "$(cat /work/client-singbox.pid)"; sleep 0.2; /mature/sing-box run -c /work/private/client.json >> /work/client-singbox.log 2>&1 & echo $! > /work/client-singbox.pid',
      ]);
    else await delay(12000);
    for (const size of group.proof_sizes) {
      const p = call(
        [
          "docker",
          "exec",
          CLIENT,
          "/lab/evolution/evo-probe-linux",
          "fetch",
          URL,
          String(size),
        ],
        { allowFailure: true, timeout: 30000 },
      );
      let parsed;
      try {
        parsed = JSON.parse(p.stdout);
      } catch {
        parsed = { ok: false, process: p };
      }
      row.proofs.push(parsed);
      await delay(2200);
    }
    await delay(1250);
    call(["docker", "stop", "--signal", "SIGINT", capture], {
      allowFailure: true,
    });
    row.finished = new Date().toISOString();
    row.native_log_tail = docker(
      "exec",
      CLIENT,
      "/bin/sh",
      "-c",
      "tail -45 /lab/dpi-v2/run/mature-native/client/belnet.log",
    );
    trials.push(row);
    save("trials.json", trials);
    console.log(
      JSON.stringify({
        group: group.id,
        split: group.split,
        ok: row.proofs.map((p) => p.ok),
        elapsed: row.proofs.map((p) => p.elapsed_ms),
      }),
    );
  }
  save("status.json", {
    status: "complete",
    real_belnet: true,
    groups: trials.length,
  });
}
main()
  .catch((e) => {
    save("failure.json", { error: String(e), at: new Date().toISOString() });
    console.error(String(e));
    process.exitCode = 1;
  })
  .finally(() => {
    for (const name of created) {
      const p = call(["docker", "logs", name], { allowFailure: true });
      fs.writeFileSync(path.join(OUT, name + ".log"), p.stdout + p.stderr);
    }
    if (created.includes(CLIENT)) {
      const p = call(
        [
          "docker",
          "exec",
          CLIENT,
          "cat",
          "/lab/dpi-v2/run/mature-native/client/belnet.log",
        ],
        { allowFailure: true },
      );
      fs.writeFileSync(path.join(OUT, "belnet.log"), p.stdout + p.stderr);
      const rules = call(["docker", "exec", CLIENT, "iptables-save"], {
        allowFailure: true,
      });
      fs.writeFileSync(
        path.join(OUT, "iptables.txt"),
        rules.stdout + rules.stderr,
      );
    }
    save("created-containers.json", created);
    for (const name of created.reverse())
      call(["docker", "rm", "-f", name], { allowFailure: true });
  });

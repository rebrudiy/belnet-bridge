"use strict";
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process"),
  crypto = require("crypto");
const ROOT = path.resolve(__dirname, "../../..");
const hash = (p) =>
  crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const save = (p, value) => {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
};
function exec(args, { input, timeout = 30000, allowFailure = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = cp.spawn(args[0], args.slice(1), {
      cwd: ROOT,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeout);
    child.stdout.on("data", (b) => (stdout += b));
    child.stderr.on("data", (b) => (stderr += b));
    child.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const result = { code, signal, stdout, stderr };
      if (code !== 0 && !allowFailure)
        reject(
          Object.assign(
            new Error(args.slice(0, 3).join(" ") + ": " + stderr.slice(-2000)),
            { result },
          ),
        );
      else resolve(result);
    });
    child.stdin.end(input);
  });
}
function args(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith("--") || argv[i + 1] === undefined)
      throw Error("Use --name value arguments");
    a[argv[i].slice(2)] = argv[i + 1];
  }
  return a;
}
function sourceHashes(dir = __dirname) {
  const out = {};
  function walk(p) {
    for (const entry of fs.readdirSync(p, { withFileTypes: true })) {
      const file = path.join(p, entry.name);
      if (
        entry.name === "review-stage-a.cjs" ||
        /\.test\.cjs$|_test\.go$/.test(entry.name)
      )
        continue;
      if (entry.isDirectory()) walk(file);
      else if (/\.(cjs|go|sh|md|json)$/.test(file))
        out[path.relative(ROOT, file)] = hash(file);
    }
  }
  walk(dir);
  return out;
}
function buildConfigs({ entries }) {
  const server = {},
    outbounds = [];
  for (let n = 1; n <= 2; n++) {
    const e = entries[n - 1],
      address = "10.88.0.1" + n;
    server[n] = {
      log: { level: "info", timestamp: true },
      inbounds: [
        {
          type: "vless",
          tag: "framed-only",
          listen: address,
          listen_port: 19444,
          users: [{ name: "g01", uuid: e.uuid, flow: "xtls-rprx-vision" }],
          tls: {
            enabled: true,
            server_name: "decoy.test",
            reality: {
              enabled: true,
              handshake: { server: "127.0.0.1", server_port: 18444 },
              private_key: e.private_key,
              short_id: [e.short_id],
            },
          },
        },
      ],
      outbounds: [{ type: "direct", tag: "framed-loopback" }],
      route: {
        rules: [
          {
            inbound: ["framed-only"],
            network: "tcp",
            ip_cidr: ["127.0.0.1/32"],
            port: [21990],
            action: "route",
            override_address: "127.0.0.1",
            override_port: 21990,
            outbound: "framed-loopback",
          },
          { action: "reject" },
        ],
      },
    };
    outbounds.push({
      type: "vless",
      tag: "entry" + n,
      server: address,
      server_port: 19444,
      uuid: e.uuid,
      flow: "xtls-rprx-vision",
      tls: {
        enabled: true,
        server_name: "decoy.test",
        utls: { enabled: true, fingerprint: "chrome" },
        reality: {
          enabled: true,
          public_key: e.public_key,
          short_id: e.short_id,
        },
      },
    });
  }
  const client = {
    log: { level: "info", timestamp: true },
    inbounds: [1, 2].map((n) => ({
      type: "direct",
      tag: "tcp-entry" + n,
      listen: "127.0.0.1",
      listen_port: 19090 + n,
      network: "tcp",
      override_address: "127.0.0.1",
      override_port: 21990,
    })),
    outbounds,
    route: {
      rules: [
        ...[1, 2].map((n) => ({
          inbound: ["tcp-entry" + n],
          network: "tcp",
          action: "route",
          outbound: "entry" + n,
        })),
        { action: "reject" },
      ],
    },
  };
  return { client, server };
}
function adapterSourceHashes() {
  const out = {};
  for (const name of fs.readdirSync(ROOT))
    if (name.endsWith(".go") && !name.endsWith("_test.go"))
      out[name] = hash(path.join(ROOT, name));
  function walk(dir) {
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      if (item.name === "testdata" || item.name.endsWith("_test.go")) continue;
      const file = path.join(dir, item.name);
      if (item.isDirectory()) walk(file);
      else if (item.isFile()) out[path.relative(ROOT, file)] = hash(file);
    }
  }
  walk(path.join(ROOT, "internal"));
  for (const name of ["go.mod", "go.sum"])
    out[name] = hash(path.join(ROOT, name));
  return out;
}
module.exports = {
  adapterSourceHashes,
  ROOT,
  hash,
  save,
  exec,
  args,
  sourceHashes,
  buildConfigs,
};

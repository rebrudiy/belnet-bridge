"use strict";
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const base = require("../../dpi-g02/runtime/common.cjs");
const ROOT = path.resolve(__dirname, "../../..");
function sourceHashes() {
  const result = {};
  const walk = (p) => {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      const file = path.join(p, e.name);
      if (e.isDirectory()) walk(file);
      else if (
        /\.(?:cjs|sh|go|json|md)$/.test(file) &&
        !/(?:\.test\.cjs|_test\.go)$/.test(file)
      )
        result[path.relative(ROOT, file)] = base.hash(file);
    }
  };
  walk(__dirname);
  for (const p of [
    "lab/dpi-g02/runtime/common.cjs",
    "lab/dpi-g02/runtime/capture.cjs",
  ])
    result[p] = base.hash(path.join(ROOT, p));
  return result;
}
function idOf(group) {
  const id = group.group_id || group.id;
  if (!/^[-a-z0-9]{1,80}$/.test(id || ""))
    throw Error("Invalid group identifier");
  return id;
}
function splitOf(group) {
  if (!["train", "validation", "test"].includes(group.split))
    throw Error("Invalid split");
  return group.split;
}
function proxyConfig(group, entry = 1) {
  return {
    group_id: idOf(group),
    public_authorities: group.public_authorities || [
      "www.google.com:443",
      "*.google.com:443",
      "*.gstatic.com:443",
      "www.youtube.com:443",
      "*.youtube.com:443",
      "*.googlevideo.com:443",
      "*.ytimg.com:443",
      "*.ggpht.com:443",
      "*.googleapis.com:443",
      "speed.cloudflare.com:443",
      "www.rfc-editor.org:443",
      "rfc-editor.org:443",
    ],
    lab_mappings: {
      "entry1.test:443": "10.88.0.11:443",
      "entry2.test:443": "10.88.0.12:443",
      "decoy.test:443": "10.88.0.1" + entry + ":443",
    },
    max_connections: 64,
    dial_timeout_ms: 5000,
    max_tunnel_ms: 120000,
  };
}
function coreConfigs(credentials, proxyIP) {
  const servers = {},
    outbounds = [
      {
        type: "http",
        tag: "observer-connect",
        server: proxyIP,
        server_port: 8080,
      },
    ];
  for (let n = 1; n <= 2; n++) {
    const c = credentials[n - 1];
    servers[n] = {
      log: { level: "info", timestamp: true },
      inbounds: [
        {
          type: "vless",
          tag: "framed-only",
          listen: "10.88.0.1" + n,
          listen_port: 443,
          users: [{ name: "g03", uuid: c.uuid, flow: "xtls-rprx-vision" }],
          tls: {
            enabled: true,
            server_name: "decoy.test",
            reality: {
              enabled: true,
              handshake: { server: "127.0.0.1", server_port: 18444 },
              private_key: c.private_key,
              short_id: [c.short_id],
            },
          },
        },
      ],
      outbounds: [{ type: "direct", tag: "local-frame" }],
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
            outbound: "local-frame",
          },
          { action: "reject" },
        ],
      },
    };
    outbounds.push({
      type: "vless",
      tag: "entry" + n,
      server: "entry" + n + ".test",
      server_port: 443,
      uuid: c.uuid,
      flow: "xtls-rprx-vision",
      detour: "observer-connect",
      tls: {
        enabled: true,
        server_name: "decoy.test",
        utls: { enabled: true, fingerprint: "chrome" },
        reality: {
          enabled: true,
          public_key: c.public_key,
          short_id: c.short_id,
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
      rules: [1, 2].map((n) => ({
        inbound: ["tcp-entry" + n],
        action: "route",
        outbound: "entry" + n,
      })),
      final: "observer-connect",
    },
  };
  return { servers, client };
}
function randomNonce() {
  return crypto.randomBytes(32).toString("hex");
}
module.exports = {
  ...base,
  ROOT,
  sourceHashes,
  idOf,
  splitOf,
  proxyConfig,
  coreConfigs,
  randomNonce,
};

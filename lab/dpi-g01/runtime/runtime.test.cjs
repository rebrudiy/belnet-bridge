"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("fs"),
  path = require("path"),
  os = require("os"),
  { EventEmitter } = require("events"),
  { PassThrough } = require("stream");
const {
  ROOT,
  hash,
  save,
  sourceHashes,
  adapterSourceHashes,
  buildConfigs,
} = require("./common.cjs");
const { validateFreeze } = require("./stage-a.cjs");
const { Capture } = require("./capture.cjs");
const PLAN = require("./plan.json");
function temporary() {
  fs.mkdirSync(path.join(ROOT, "lab/dpi-g01/run"), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, "lab/dpi-g01/run/unit-"));
}
test("TCP-only configs reject UDP and arbitrary requested destinations", () => {
  const c = buildConfigs({
    entries: [1, 2].map((i) => ({
      uuid: "uuid" + i,
      short_id: "abcd",
      private_key: "private",
      public_key: "public",
    })),
  });
  for (const s of Object.values(c.server)) {
    const [allow, reject] = s.route.rules;
    assert.equal(allow.network, "tcp");
    assert.deepEqual(allow.ip_cidr, ["127.0.0.1/32"]);
    assert.deepEqual(allow.port, [21990]);
    assert.equal(allow.override_address, "127.0.0.1");
    assert.equal(allow.override_port, 21990);
    assert.equal(reject.action, "reject");
  }
  for (const i of c.client.inbounds) {
    assert.equal(i.network, "tcp");
    assert.equal(i.listen, "127.0.0.1");
  }
  for (const o of c.client.outbounds) {
    assert.equal(o.tls.utls.fingerprint, "chrome");
    assert.equal(o.packet_encoding, undefined);
    assert.equal(o.tls.insecure, undefined);
  }
});
test("Finite engineering plan has four fresh deployments and exact outage/phase bounds", () => {
  assert.equal(PLAN.groups.length, 4);
  assert.deepEqual(
    PLAN.groups.map((x) => x.kind),
    ["v2", "framed", "framed", "v2"],
  );
  assert.equal(PLAN.phase_ms, 45000);
  assert.equal(PLAN.interruption_ms, 2000);
  assert.equal(PLAN.warmup_start_ms.length, 3);
  assert.equal(PLAN.phase_fetch_start_ms.length, 8);
  assert.ok(
    PLAN.phase_fetch_start_ms.every(
      (ms) => ms + PLAN.phase_fetch_timeout_ms <= PLAN.phase_ms,
    ),
  );
  assert.equal(PLAN.pcap_max_bytes, 256 * 1024 * 1024);
});
test("Freeze rejects missing binary/source/config hashes without invoking Docker", () => {
  const dir = temporary();
  try {
    const binary = path.join(dir, "binary");
    fs.writeFileSync(
      binary,
      Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]),
    );
    const buildLog = path.join(dir, "build.log");
    fs.writeFileSync(buildLog, "unit fixture only; no experiment");
    const asset = path.join(dir, "asset");
    fs.writeFileSync(asset, "fixture");
    const prep = {
      directory: dir,
      assets_sha256: { asset: hash(asset) },
      native_belnet: { sha256: "a".repeat(64) },
      probe: { path: binary, sha256: hash(binary) },
      sing_box: { path: binary, sha256: hash(binary), libraries: [] },
    };
    const descriptor = path.join(dir, "preparation.json");
    save(descriptor, prep);
    const freeze = {
      schema: "belnet-g01-stage-a/v1",
      stage: "A",
      run_id: "unit-only",
      frozen_at: new Date().toISOString(),
      protocol_sha256: hash(path.join(ROOT, "lab/dpi-g01/PROTOCOL.md")),
      plan_sha256: hash(path.join(__dirname, "plan.json")),
      source_sha256: sourceHashes(),
      adapter_source_sha256: adapterSourceHashes(),
      baseline_enforcement_disabled: true,
      baseline_servers: [
        { live_binary_sha256: "a".repeat(64) },
        { live_binary_sha256: "b".repeat(64) },
      ],
      build: {
        command: ["unit-fixture"],
        log: { path: buildLog, sha256: hash(buildLog) },
      },
      prepared: { path: descriptor, sha256: hash(descriptor) },
      adapter: { path: binary, sha256: hash(binary) },
    };
    const file = path.join(dir, "freeze.json");
    save(file, freeze);
    assert.ok(validateFreeze(file));
    const missing = structuredClone(freeze);
    delete missing.adapter.sha256;
    save(file, missing);
    assert.throws(() => validateFreeze(file), /binary SHA/);
    const changed = structuredClone(freeze);
    changed.source_sha256[Object.keys(changed.source_sha256)[0]] = "0".repeat(
      64,
    );
    save(file, changed);
    assert.throws(() => validateFreeze(file), /Source changed/);
    save(file, freeze);
    fs.appendFileSync(asset, "changed");
    assert.throws(() => validateFreeze(file), /Prepared asset changed/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
function fakeCapture(dir, overrides = {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => {};
  const cap = new Capture({
    name: "unit-capture",
    network: "unit",
    image: "unit",
    directory: dir,
    file: "capture",
    filter: [],
    maxBytes: 10,
    spawn: () => child,
    run: async () => ({ code: 0 }),
    timeouts: { ready: 30, stop: 20, close: 10, kill: 20, final: 10 },
    ...overrides,
  });
  return { cap, child };
}
test("Capture readiness requires actual listening banner", async () => {
  const dir = temporary();
  try {
    const { cap, child } = fakeCapture(dir);
    let ready = false;
    const waiting = cap.ready().then(() => (ready = true));
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(ready, false);
    child.stderr.write("tcpdump: listening on eth0, link-type EN10MB\n");
    await waiting;
    assert.equal(ready, true);
    child.stderr.write(
      "1 packets captured\n1 packets received by filter\n0 packets dropped by kernel\n",
    );
    child.emit("close", 0, null);
    await cap.stop();
    assert.equal(cap.result().incomplete, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
test("Bounded capture never overwrites prefix; stalled cleanup is finite/incomplete", async () => {
  const dir = temporary();
  try {
    const { cap, child } = fakeCapture(dir);
    child.stderr.write("listening on eth0\n");
    await cap.ready();
    child.stdout.write(Buffer.from("abcdefghijklmnop"));
    await cap.stop();
    assert.equal(
      fs.readFileSync(path.join(dir, "capture"), "utf8"),
      "abcdefghij",
    );
    assert.equal(cap.result().capped, true);
    assert.equal(cap.result().forced_cleanup, true);
    assert.equal(cap.result().incomplete, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

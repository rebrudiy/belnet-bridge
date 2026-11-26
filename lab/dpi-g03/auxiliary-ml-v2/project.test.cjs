"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), cp = require("node:child_process"), crypto = require("node:crypto");
const { build, main, argumentsFor } = require("./project.cjs");
const ROOT = path.resolve(__dirname, "../../.."), OBS = "lab/dpi-g03/observer-v4/tooling/TOOLING.json";
const hash = b => crypto.createHash("sha256").update(b).digest("hex"), raw = x => Buffer.from(JSON.stringify(x, null, 2) + "\n");
function fixture() {
  const tooling = JSON.parse(fs.readFileSync(path.join(__dirname, "tooling/TOOLING.json"))), observerRaw = fs.readFileSync(path.join(ROOT, OBS)), observer = JSON.parse(observerRaw), auxiliaryBinaryRaw = Buffer.from("synthetic test ELF bytes; never executed");
  tooling.created_at = "2023-11-14T22:13:19Z";
  tooling.binary.auxiliary = { sha256: hash(auxiliaryBinaryRaw), versioned_path: "unused-in-pure-build" };
  const groups = Array.from({ length: 71 }, (_, i) => ({ group_id: "synthetic-" + i, source_workload_id: "source-" + i, split: i < 46 ? "train" : "validation", class: i % 4 === 0 ? "belnet" : "benign", profile: "synthetic-only", scope: "primary", transport: i % 4 === 0 ? "reality" : "ordinary-tls", client_stack: "fixture", nonce: "SHOULD_NOT_BE_COPIED", seed_int: i + 1 }));
  const master = { schema: "belnet-g03-collector/v4", stage: "B1", frozen_at: "2023-11-14T22:13:20Z", measured_seconds: 80, capture_seconds: 82, prefix_grace_seconds: 2, pcap_cap_bytes: 268435456, window_offsets_seconds: [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78], groups, files_sha256: { [OBS]: hash(observerRaw), [observer.binary.observer.versioned_path]: observer.binary.observer.sha256, "/DO-NOT-READ-SYNTHETIC-PIN": "c".repeat(64) }, test_seeds_commitment: { path: "/DO-NOT-READ-VAULT", sha256: "d".repeat(64) } };
  const masterRaw = raw(master), auditorSHA = hash(fs.readFileSync(path.join(ROOT, "lab/dpi-g03/review-r4.cjs")));
  const audit = { schema: "g03-root-acquisition-review/v4", stage: "B1", freeze_sha256: hash(masterRaw), checked_utc: "2023-11-14T22:15:00Z", private_test_values_read: false, acquisition_qualified: true, expected_groups: 71, reviewed_groups: 71, errors: [], missing_groups: [], groups: groups.map(g => ({ group_id: g.group_id, acquisition_qualified: true, errors: [] })), auditor_sha256: auditorSHA, pins: Object.keys(master.files_sha256).map(p => ({ path: p, matches: true })) };
  return { masterRaw, auditRaw: raw(audit), toolingRaw: raw(tooling), observerRaw, auxiliaryBinaryRaw, auditorSHA, now: "2023-11-14T22:16:00Z" };
}
function mutate(input, field, change) { const result = { ...input }, value = JSON.parse(result[field]); change(value); result[field] = raw(value); return result; }
function withMaster(input, change) { const result = mutate(input, "masterRaw", change), a = JSON.parse(result.auditRaw); a.freeze_sha256 = hash(result.masterRaw); result.auditRaw = raw(a); return result; }
function temporary(t) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aux-project-test-")); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir; }
function writeCLI(t, input) {
  const dir = temporary(t), tool = JSON.parse(input.toolingRaw), binary = path.join(dir, "synthetic-auxiliary"); fs.writeFileSync(binary, input.auxiliaryBinaryRaw); tool.binary.auxiliary.versioned_path = binary;
  const paths = {}; for (const [flag, bytes] of [["master", input.masterRaw], ["audit", input.auditRaw], ["tooling", raw(tool)]]) { paths[flag] = path.join(dir, flag + ".json"); fs.writeFileSync(paths[flag], bytes); }
  return { dir, args: ["--master", paths.master, "--audit", paths.audit, "--tooling", paths.tooling, "--out-dir", path.join(dir, "output"), "--binary-key", "auxiliary"], out: path.join(dir, "output") };
}
test("canonical independent projection preserves pre-capture clock and keeps default release gated", () => {
  const input = fixture(), result = build(input), master = JSON.parse(input.masterRaw);
  assert.equal(result.projection.frozen_at, master.frozen_at); assert.notEqual(result.projection.frozen_at, input.now);
  assert.equal(result.release.read_authorized, false); assert.equal(result.release.fit_authorized, false);
  assert.equal(result.projection.data_release_sha256, hash(result.releaseRaw));
  assert.equal(result.bindings.auxiliary_projection_sha256, hash(result.projectionRaw)); assert.notEqual(result.bindings.auxiliary_projection_sha256, hash(input.masterRaw));
  assert.equal(result.projection.groups.length, 71); assert.ok(result.projection.groups.every(g => !("nonce" in g) && !("seed_int" in g)));
  assert.equal(result.projection.stage_a_viability, "proceed"); assert.equal(result.projection.data_release_path, "data-release.json");
});
test("authorization is explicit and cannot enable fit without read", () => {
  assert.throws(() => build({ ...fixture(), fitAuthorized: true }), /requires_read/);
  const result = build({ ...fixture(), readAuthorized: true, fitAuthorized: true });
  assert.equal(result.release.read_authorized, true); assert.equal(result.release.fit_authorized, true);
});
test("unfinished, censored, missing or duplicate group audit never creates a release", () => {
  for (const change of [a => { a.reviewed_groups = 70; }, a => { a.acquisition_qualified = false; }, a => { a.errors = ["lost capture"]; }, a => { a.missing_groups = ["synthetic-70"]; }, a => { a.groups[3].acquisition_qualified = false; }, a => { a.groups[3].errors = ["censor"]; }, a => { a.groups[1] = a.groups[0]; }]) assert.throws(() => build(mutate(fixture(), "auditRaw", change)), /required|qualify/);
});
test("Q, test, diagnostic and paired-source split leakage are rejected", () => {
  for (const change of [m => { m.stage = "Q"; }, m => { m.groups[0].split = "test"; }, m => { m.groups[0].scope = "diagnostic"; }, m => { m.groups[46].source_workload_id = m.groups[0].source_workload_id; }, m => { m.groups[0].transport = "ordinary-tls"; }]) assert.throws(() => build(withMaster(fixture(), change)), /only|rejected|leakage|mismatch/);
});
test("master, root auditor and complete source pin census are cryptographically bound", () => {
  for (const change of [a => { a.freeze_sha256 = "f".repeat(64); }, a => { a.auditor_sha256 = "e".repeat(64); }, a => { a.pins.pop(); }, a => { a.pins[0].matches = false; }, a => { a.pins[1] = a.pins[0]; }]) assert.throws(() => build(mutate(fixture(), "auditRaw", change)), /binding|pin/);
});
test("fixed ML/config/coverage, selected executable and frozen observer cannot drift", () => {
  for (const change of [m => { m.hyperparameters.depth++; }, m => { m.coverage_semantics_sha256 = "f".repeat(64); }, m => { m.readonly_library_source.sha256 = "f".repeat(64); }, m => { m.created_at = "2023-11-14T22:13:21Z"; }, m => { m.binary.auxiliary.sha256 = "f".repeat(64); }]) assert.throws(() => build(mutate(fixture(), "toolingRaw", change)), /mismatch|precede/);
  assert.throws(() => build(withMaster(fixture(), m => { m.files_sha256[OBS] = "f".repeat(64); })), /observer_not_pinned/);
});
test("release chronology cannot be backdated or fabricated before completed audit", () => {
  assert.throws(() => build({ ...fixture(), now: "2023-11-14T22:14:59Z" }), /follow/);
  assert.throws(() => build(mutate(fixture(), "auditRaw", a => { a.checked_utc = "2023-11-14T22:13:19Z"; })), /follow/);
});
test("working CLI emits only two canonical files without opening sentinel index/group/vault paths", t => {
  const input = fixture(), f = writeCLI(t, input), summary = main(f.args);
  assert.deepEqual(fs.readdirSync(f.out).sort(), ["auxiliary-b1.json", "data-release.json"]);
  const projection = JSON.parse(fs.readFileSync(path.join(f.out, "auxiliary-b1.json"))), releaseRaw = fs.readFileSync(path.join(f.out, "data-release.json"));
  assert.equal(projection.data_release_sha256, hash(releaseRaw)); assert.equal(summary.auxiliary_projection_sha256, hash(fs.readFileSync(path.join(f.out, "auxiliary-b1.json"))));
  assert.equal(summary.actual_group_or_index_or_vault_files_read, false); assert.equal(summary.read_authorized, false);
  assert.throws(() => main(f.args), /no_overwrite/);
  assert.throws(() => argumentsFor(["--index", "DO-NOT-OPEN"]), /unknown/);
});
test("existing Go ABI accepts projection then blocks before opening index when read flag false", t => {
  const f = writeCLI(t, fixture()); main(f.args);
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "tooling/TOOLING.json"))), executable = path.join(ROOT, manifest.binary.auxiliary.versioned_path);
  const result = cp.spawnSync(executable, ["fit", "-freeze", path.join(f.out, "auxiliary-b1.json"), "-index", path.join(f.dir, "DO-NOT-OPEN-INDEX"), "-out", path.join(f.dir, "NO-ACTUAL-MODEL.json")], { encoding: "utf8" });
  assert.equal(result.status, 1); assert.match(result.stderr, /actual auxiliary data remains gated/); assert.doesNotMatch(result.stderr, /DO-NOT-OPEN-INDEX/);
  assert.equal(fs.existsSync(path.join(f.dir, "NO-ACTUAL-MODEL.json")), false);
});

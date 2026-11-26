"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { inspectPCAP, inspectGroup, pinLocation, audit } = require("./review-checkpoint.cjs");
function capture() {
  const raw = Buffer.alloc(44);
  Buffer.from("d4c3b2a1", "hex").copy(raw);
  raw.writeUInt16LE(2, 4); raw.writeUInt16LE(4, 6);
  raw.writeUInt32LE(65535, 16); raw.writeUInt32LE(1, 20);
  raw.writeUInt32LE(4, 32); raw.writeUInt32LE(4, 36);
  return raw;
}
function fixture() {
  const frozen = { group_id: "dev-one", split: "train", class: "benign", profile: "ordinary" };
  const pcap = inspectPCAP(capture());
  const report = { schema: 3, version: "g03-observer-v1", metadata: { group_id: "dev-one", split: "train", freeze_sha256: "freeze" }, pcap_sha256: pcap.sha256, counters: { packets: 1 }, coverage_complete: true, flows: [] };
  const record = { group: { ...frozen }, errors: [], captures: [{ name: "one-capture", code: 0, captured: 1, received_by_filter: 1, dropped_by_kernel: 0, bytes: pcap.bytes }], observer_process: { code: 0 }, measurement_start: { unix_micros: 1_000_000 }, capture_end: { unix_micros: 83_000_000 } };
  return { frozen, pcap, report, record };
}
test("reads complete PCAP, retains independent raw binding", () => {
  const p = inspectPCAP(capture());
  assert.equal(p.packets, 1); assert.equal(p.truncated_packets, 0); assert.equal(p.sha256.length, 64);
  assert.notEqual(inspectPCAP(Buffer.concat([capture(), capture().subarray(24)])).sha256, p.sha256);
});
test("partial record headers and bodies never count as complete", () => {
  assert.throws(() => inspectPCAP(capture().subarray(0, 30)), /partial_packet_header/);
  assert.throws(() => inspectPCAP(capture().subarray(0, 43)), /partial_packet_body/);
  const invalid = capture(); invalid.writeUInt32LE(65536, 32);
  assert.throws(() => inspectPCAP(invalid), /invalid_packet_lengths/);
});
test("snaplen loss is explicit even when packet counters match", () => {
  const raw = capture(); raw.writeUInt32LE(8, 36);
  const f = fixture(); f.pcap = inspectPCAP(raw); f.report.pcap_sha256 = f.pcap.sha256;
  assert.ok(inspectGroup(f.record, f.report, f.pcap, f.frozen, "freeze").errors.includes("snaplen_truncated_packets"));
});
test("clean synthetic acquisition qualifies without claiming a DPI result", () => {
  const f = fixture(), r = inspectGroup(f.record, f.report, f.pcap, f.frozen, "freeze");
  assert.equal(r.acquisition_qualified, true); assert.equal("detected" in r, false);
});
test("browser timeout remains incomplete despite completed measurement horizon", () => {
  const f = fixture(); f.record.browser = { timeout: true };
  const r = inspectGroup(f.record, f.report, f.pcap, f.frozen, "freeze");
  assert.equal(r.acquisition_qualified, false); assert.ok(r.errors.includes("browser_lifecycle_incomplete"));
});
test("zero kernel drops cannot rescue unequal counters or changed raw bytes", () => {
  const f = fixture(); f.record.captures[0].received_by_filter = 2; f.report.pcap_sha256 = "wrong";
  const r = inspectGroup(f.record, f.report, f.pcap, f.frozen, "freeze");
  assert.ok(r.errors.includes("received_vs_saved_unknown")); assert.ok(r.errors.includes("observer_raw_binding_mismatch"));
});
test("old observer failure survives passive audit and provenance mismatch fails", () => {
  const f = fixture(); f.report.coverage_complete = false;
  f.report.flows = [{ issues: ["non_monotonic_flow_clock"] }];
  const r = inspectGroup(f.record, f.report, f.pcap, f.frozen, "another-freeze");
  assert.ok(r.errors.includes("frozen_observer_incomplete"));
  assert.ok(r.errors.includes("observer_freeze_binding_mismatch"));
  assert.deepEqual(r.observer_issues, ["non_monotonic_flow_clock"]);
});
test("collector archives source text and pins external applications/binaries in place", () => {
  const freeze = { source_archive: "/tmp/g03-source" };
  assert.deepEqual(pinLocation(freeze, "lab/source.go"), { filename: "/tmp/g03-source/lab/source.go", kind: "archived_source" });
  assert.deepEqual(pinLocation(freeze, "/Applications/Chrome"), { filename: "/Applications/Chrome", kind: "current_external_pin" });
  assert.equal(pinLocation(freeze, "out/observer-linux").kind, "current_binary_pin");
  assert.throws(() => pinLocation(freeze, "../outside.go"), /archive_pin_path_escape/);
});
test("empty declarations cannot qualify; test references fail before any group or pin read", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "g03-checkpoint-test-"));
  try {
    const filename = path.join(dir, "freeze.json");
    const freeze = { schema: "belnet-g03-collector/v1", stage: "B1", measured_seconds: 80, capture_seconds: 82, groups: [], files_sha256: { "nonexistent.go": "pin" } };
    fs.writeFileSync(filename, JSON.stringify(freeze));
    assert.throws(() => audit("/nonexistent-group-root", filename), /nonempty_frozen_G03_acquisition_required/);
    freeze.groups = [{ group_id: "held-out", split: "test" }];
    fs.writeFileSync(filename, JSON.stringify(freeze));
    assert.throws(() => audit("/nonexistent-group-root", filename), /test_references_rejected_before_group_reads/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

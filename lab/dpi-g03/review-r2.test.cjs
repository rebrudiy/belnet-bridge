"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { groupChecks } = require("./review-r2.cjs");
function fixture() {
  const g = { group_id: "ordinary", split: "train", scope: "primary", class: "benign", profile: "ordinary", client_stack: "go-wss" };
  const f = { pcap_cap_bytes: 256 * 1024 * 1024, window_offsets_seconds: [0, 78] };
  const start = 1_000_000, raw = { packets: 2, bytes: 100, sha256: "a".repeat(64), truncated_packets: 0 };
  const metadata = { ...g, freeze_sha256: "freeze", measurement_start_unix_micros: start, measured_seconds: 80, prefix_grace_seconds: 2, capture_cap_bytes: f.pcap_cap_bytes, window_offsets_seconds: [0, 78] };
  const o = { schema: 4, version: "g03-observer-v2", pcap_sha256: raw.sha256, counters: { packets: 2 }, ordering_semantics_sha256: "b".repeat(64), metadata, coverage_complete: true };
  const l = { schema: 2, version: "g03-longflow-v2", pcap_sha256: raw.sha256, ordering_semantics_sha256: o.ordering_semantics_sha256, metadata: { ...metadata }, source_observer_coverage_complete: true };
  const r = { group: { ...g }, errors: [], captures: [{ name: "ordinary-capture", code: 0, captured: 2, received_by_filter: 2, dropped_by_kernel: 0, bytes: 100 }], observer_process: { code: 0 }, longflow_process: { code: 0 }, measurement_start: { unix_micros: start }, capture_start: { unix_micros: start - 10 }, quiesce: { started_unix_micros: start + 82_000_000, finished_unix_micros: start + 82_001_000, result: "ok", process_code: 0 }, drain_end: { unix_micros: start + 82_501_000 }, capture_end: { unix_micros: start + 82_600_000 } };
  return { g, r, o, l, raw, f };
}
function errors(x) { return groupChecks(x.g, x.r, x.o, x.l, x.raw, x.f, "freeze"); }
test("complete acquisition fixture qualifies without a classifier verdict", () => assert.deepEqual(errors(fixture()), []));
test("zero drops and complete reporters cannot rescue a packet accounting mismatch", () => {
  const x = fixture(); x.r.captures[0].received_by_filter++;
  assert.ok(errors(x).includes("outer_capture_accounting_or_lifecycle"));
});
test("quiesce before the horizon and short drain are separate acquisition failures", () => {
  const x = fixture(); x.r.quiesce.started_unix_micros = x.r.measurement_start.unix_micros + 79_000_000;
  assert.ok(errors(x).includes("VM_horizon_quiesce_or_drain"));
  const y = fixture(); y.r.drain_end.unix_micros = y.r.quiesce.finished_unix_micros + 499_999;
  assert.ok(errors(y).includes("VM_horizon_quiesce_or_drain"));
});
test("metadata provenance and raw bindings cannot be silently relabeled", () => {
  const x = fixture(); x.l.metadata = { ...x.l.metadata, split: "test" };
  assert.ok(errors(x).includes("report_frozen_metadata"));
  const y = fixture(); y.o.pcap_sha256 = "c".repeat(64);
  assert.ok(errors(y).includes("raw_report_binding"));
});
test("saved Chrome evidence does not excuse forced teardown", () => {
  const x = fixture(); x.g.client_stack = "chrome"; x.r.group.client_stack = "chrome";
  x.r.browser_acquisition_complete = true; x.r.browser = { code: 0 };
  x.r.browser_teardown = { result: "exited", errors: [], signals: ["SIGTERM"] };
  assert.ok(errors(x).includes("browser_acquisition_or_teardown"));
});
test("native final snapshot must span the primary horizon and finish before quiesce", () => {
  const x = fixture(); x.g.class = "belnet"; x.r.group.class = "belnet";
  x.r.snapshots = [{ label: "t81000", clock: { unix_micros: x.r.measurement_start.unix_micros + 79_000_000 }, snapshot_finished: { unix_micros: x.r.measurement_start.unix_micros + 79_100_000 } }];
  assert.ok(errors(x).includes("native_postprimary_snapshot"));
  x.r.snapshots[0].clock.unix_micros = x.r.measurement_start.unix_micros + 81_000_000;
  x.r.snapshots[0].snapshot_finished.unix_micros = x.r.measurement_start.unix_micros + 81_100_000;
  assert.ok(!errors(x).includes("native_postprimary_snapshot"));
});

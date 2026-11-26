"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict");
const { captureErrors } = require("./quality.cjs");
const good = () => ({
  captures: [
    {
      name: "group-capture",
      code: 0,
      capped: false,
      forced_cleanup: false,
      dropped_by_kernel: 0,
      captured: 10,
      received_by_filter: 10,
    },
  ],
  workloads: [{ data: { error: "application unavailable" } }],
});
test("application failure is not invented capture failure", () =>
  assert.deepEqual(captureErrors(good(), { counters: { packets: 10 } }), []));
test("zero kernel loss does not excuse missing saved packets", () => {
  const r = good();
  r.captures[0].received_by_filter = 11;
  assert(
    captureErrors(r, { counters: { packets: 10 } }).includes(
      "received_vs_saved_mismatch_unknown",
    ),
  );
});
test("forced but parseable capture stays ineligible", () => {
  const r = good();
  r.captures[0].forced_cleanup = true;
  assert(
    captureErrors(r, { counters: { packets: 10 } }).includes(
      "outer_capture_forced_cleanup",
    ),
  );
});
test("missing counters or observer agreement never count as zero", () => {
  const r = good();
  r.captures[0].dropped_by_kernel = null;
  assert(
    captureErrors(r, { counters: { packets: 9 } }).includes(
      "kernel_drop_counter_missing",
    ),
  );
  assert(
    captureErrors(r, { counters: { packets: 9 } }).includes(
      "observer_vs_tcpdump_packet_count_mismatch",
    ),
  );
});

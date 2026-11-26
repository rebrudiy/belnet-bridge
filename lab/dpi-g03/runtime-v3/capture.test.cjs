"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  { statsFrom } = require("./capture.cjs");
test("all live/final statistics remain separate; final counters win", () => {
  const s = statsFrom(
    "1 packets captured\n2 packets received by filter\n0 packets dropped by kernel\nnoise\n2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n",
  );
  assert.equal(s.length, 2);
  assert.equal(s[0].captured, 1);
  assert.equal(s.at(-1).captured, 2);
});
test("partial live statistics cannot masquerade as a completed snapshot", () =>
  assert.equal(
    statsFrom("3 packets captured\n4 packets received by filter\n").length,
    0,
  ));
const { Capture } = require("./capture.cjs");
function fakeDrain(snapshots) {
  const c = Object.create(Capture.prototype);
  c.statSnapshots = [];
  c.capped = false;
  c.forced = false;
  let i = 0;
  c.statistics = async () => {
    const s = snapshots[Math.min(i++, snapshots.length - 1)];
    c.statSnapshots.push(s);
    return s;
  };
  return c;
}
test("drain waits through pending kernel packets until two stable equal snapshots", async () => {
  const c = fakeDrain([
    { captured: 1, received_by_filter: 2, dropped_by_kernel: 0 },
    { captured: 2, received_by_filter: 2, dropped_by_kernel: 0 },
    { captured: 2, received_by_filter: 2, dropped_by_kernel: 0 },
  ]);
  const r = await c.drain({ budgetMS: 100, stableMS: 1 });
  assert.equal(r.complete, true);
  assert.equal(r.snapshots.length, 3);
});
test("changing or mismatched counters exhaust finite drain without a pass", async () => {
  const c = fakeDrain([
    { captured: 1, received_by_filter: 2, dropped_by_kernel: 0 },
  ]);
  const r = await c.drain({ budgetMS: 8, stableMS: 1 });
  assert.equal(r.complete, false);
  assert.equal(r.error, "drain_budget_expired");
});
test("reported capture loss fails drain immediately and cannot recover by waiting", async () => {
  const c = fakeDrain([
    { captured: 2, received_by_filter: 2, dropped_by_kernel: 1 },
  ]);
  assert.equal((await c.drain({ budgetMS: 50, stableMS: 1 })).complete, false);
  assert.equal(c.statSnapshots.length, 1);
});
test("final report uses last snapshot rather than earlier pending snapshot", () => {
  const c = fakeDrain([]);
  Object.assign(c, {
    stderr:
      "1 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n",
    finalStatisticsOffset:
      "1 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n"
        .length,
    code: 0,
    bytes: 1,
    maxBytes: 10,
    forced: false,
  });
  const r = c.result();
  assert.equal(r.captured, 2);
  assert.equal(r.received_by_filter, 2);
  assert.equal(r.incomplete, false);
});
test("singular packet statistics are supported", () =>
  assert.deepEqual(
    statsFrom(
      "1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n",
    )[0],
    { captured: 1, received_by_filter: 1, dropped_by_kernel: 0 },
  ));

test("live counters cannot substitute for missing final SIGINT statistics", () => {
  const c = fakeDrain([]);
  const live =
    "2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n";
  Object.assign(c, {
    stderr: live,
    finalStatisticsOffset: live.length,
    code: 0,
    forced: false,
  });
  const r = c.result();
  assert.equal(r.final_statistics_complete, false);
  assert.equal(r.captured, null);
  assert.equal(r.incomplete, true);
});
test("partial final statistics remain unknown even after healthy live snapshots", () => {
  const c = fakeDrain([]);
  const live =
    "2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n";
  Object.assign(c, {
    stderr: live + "2 packets captured\n2 packets received by filter\n",
    finalStatisticsOffset: live.length,
    code: 0,
    forced: false,
  });
  const r = c.result();
  assert.equal(r.final_statistics_complete, false);
  assert.equal(r.dropped_by_kernel, null);
});
test("stable wait is clipped to remaining total budget", async () => {
  const c = fakeDrain([
    { captured: 1, received_by_filter: 2, dropped_by_kernel: 0 },
  ]);
  const start = performance.now();
  const r = await c.drain({ budgetMS: 20, stableMS: 120 });
  assert.equal(r.complete, false);
  assert(performance.now() - start < 80);
});
test("hung statistics RPC cannot extend the total drain indefinitely", async () => {
  const c = Object.create(Capture.prototype);
  Object.assign(c, {
    stderr: "",
    statSnapshots: [],
    run: () => new Promise(() => {}),
    capped: false,
    forced: false,
  });
  const start = performance.now();
  const r = await c.drain({ budgetMS: 20, stableMS: 1 });
  assert.equal(r.complete, false);
  assert(performance.now() - start < 80);
});

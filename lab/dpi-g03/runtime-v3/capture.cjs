"use strict";
// New capture revision. Older frozen Capture implementations are unchanged.
const cp = require("child_process");
const { Capture: Base } = require("../../dpi-g02/runtime/capture.cjs");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function beforeDeadline(call, deadline, label) {
  const remaining = deadline - performance.now();
  if (remaining <= 0) throw Error(label);
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(call),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error(label)), remaining);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function statsFrom(text) {
  const result = [];
  const re =
    /(\d+) packets? captured\s+(\d+) packets? received by filter\s+(\d+) packets? dropped by kernel/g;
  let m;
  while ((m = re.exec(text)))
    result.push({
      captured: Number(m[1]),
      received_by_filter: Number(m[2]),
      dropped_by_kernel: Number(m[3]),
    });
  return result;
}
class Capture extends Base {
  constructor(options) {
    const spawn = options.spawn || cp.spawn;
    super({
      ...options,
      spawn: (command, argv, opts) => {
        const p = argv.indexOf("-U");
        if (p < 0) throw Error("Capture launch signature changed");
        const actual = [...argv];
        actual.splice(p, 0, "--immediate-mode");
        return spawn(command, actual, opts);
      },
    });
    this.statSnapshots = [];
    this.drainResult = null;
  }
  async statistics(deadline = performance.now() + 2500) {
    const start = this.stderr.length,
      before = statsFrom(this.stderr).length;
    const rpc = await beforeDeadline(
      () =>
        this.run(["docker", "kill", "--signal", "SIGUSR1", this.name], {
          allowFailure: true,
          timeout: Math.max(1, Math.min(1500, deadline - performance.now())),
        }),
      deadline,
      "tcpdump statistics RPC deadline",
    );
    if (rpc.code !== 0)
      throw Error("Could not request tcpdump live statistics");
    const replyDeadline = Math.min(deadline, performance.now() + 1000);
    while (performance.now() < replyDeadline) {
      const all = statsFrom(this.stderr);
      if (all.length > before) {
        const s = {
          ...all.at(-1),
          observed_host_utc: new Date().toISOString(),
          clock_scope: "host_lifecycle_only_not_packet_clock",
        };
        this.statSnapshots.push(s);
        return s;
      }
      if (this.finished) throw Error("Capture exited during statistics drain");
      await wait(Math.max(0, Math.min(10, replyDeadline - performance.now())));
    }
    throw Error(
      "tcpdump live statistics deadline: " + this.stderr.slice(start),
    );
  }
  async drain({ budgetMS = 2500, stableMS = 100 } = {}) {
    if (
      !Number.isFinite(budgetMS) ||
      budgetMS <= 0 ||
      budgetMS > 2500 ||
      !Number.isFinite(stableMS) ||
      stableMS < 0
    )
      throw Error("Invalid bounded drain options");
    const start = performance.now(),
      deadline = start + budgetMS;
    let previous = null,
      error = null,
      complete = false;
    try {
      while (performance.now() - start < budgetMS) {
        const s = await beforeDeadline(
          () => this.statistics(deadline),
          deadline,
          "capture statistics deadline",
        );
        if (s.dropped_by_kernel !== 0 || this.capped || this.forced)
          throw Error("Capture loss/cap during drain");
        if (
          previous &&
          s.captured === s.received_by_filter &&
          previous.captured === previous.received_by_filter &&
          s.captured === previous.captured &&
          performance.now() - start <= budgetMS
        ) {
          complete = true;
          break;
        }
        previous = s;
        await wait(
          Math.max(0, Math.min(stableMS, deadline - performance.now())),
        );
      }
    } catch (e) {
      error = e.message;
    }
    const elapsed = performance.now() - start;
    if (elapsed > budgetMS) complete = false;
    if (!complete && !error) error = "drain_budget_expired";
    this.drainResult = {
      complete,
      elapsed_ms: elapsed,
      budget_ms: budgetMS,
      stable_ms: stableMS,
      snapshots: this.statSnapshots,
      error,
    };
    return this.drainResult;
  }
  async stop() {
    if (this.finalStatisticsOffset === undefined) {
      this.finalStatisticsOffset = this.stderr.length;
      this.stopStatisticsFrontierHostUTC = new Date().toISOString();
    }
    return super.stop();
  }
  result() {
    const r = super.result(),
      hasFrontier = Number.isSafeInteger(this.finalStatisticsOffset),
      finalText = hasFrontier
        ? this.stderr.slice(this.finalStatisticsOffset)
        : "",
      last = statsFrom(finalText).at(-1);
    r.final_statistics_complete = !!last;
    r.final_statistics_frontier = this.finalStatisticsOffset ?? null;
    r.stop_statistics_frontier_host_utc =
      this.stopStatisticsFrontierHostUTC ?? null;
    if (last) Object.assign(r, last);
    else
      Object.assign(r, {
        captured: null,
        received_by_filter: null,
        dropped_by_kernel: null,
      });
    r.incomplete =
      !r.final_statistics_complete ||
      r.capped ||
      r.forced_cleanup ||
      r.code !== 0 ||
      r.dropped_by_kernel !== 0;
    r.capture_mode = "libpcap_immediate";
    r.live_statistics = this.statSnapshots;
    r.drain = this.drainResult;
    return r;
  }
}
module.exports = { Capture, statsFrom };

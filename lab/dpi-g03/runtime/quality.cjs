"use strict";
// Acquisition quality is separate from application success or classifier verdict.
function captureErrors(record, report) {
  const c = record.captures.find((x) => /-capture$/.test(x.name)),
    errors = [];
  if (!c) return ["outer_capture_missing"];
  if (c.capped) errors.push("outer_capture_capped");
  if (c.forced_cleanup) errors.push("outer_capture_forced_cleanup");
  if (c.code !== 0) errors.push("outer_capture_nonzero_exit");
  if (c.dropped_by_kernel === null || c.dropped_by_kernel === undefined)
    errors.push("kernel_drop_counter_missing");
  else if (c.dropped_by_kernel !== 0) errors.push("kernel_drops");
  if (!Number.isInteger(c.captured) || !Number.isInteger(c.received_by_filter))
    errors.push("capture_packet_counters_missing");
  else if (c.captured !== c.received_by_filter)
    errors.push("received_vs_saved_mismatch_unknown");
  if (!report) errors.push("observer_report_missing");
  else if (report.counters?.packets !== c.captured)
    errors.push("observer_vs_tcpdump_packet_count_mismatch");
  return errors;
}
function makeIndex(records, loadReport) {
  return {
    schema: 3,
    stage: "B1",
    reports: records.map((r) => {
      const id = r.group.group_id,
        report = loadReport(id);
      return {
        group_id: id,
        split: r.group.split,
        path: id + "/windows.json",
        coverage_errors: captureErrors(r, report),
      };
    }),
  };
}
module.exports = { captureErrors, makeIndex };

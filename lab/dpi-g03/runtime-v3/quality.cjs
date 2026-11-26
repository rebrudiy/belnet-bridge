"use strict";
// Acquisition quality is separate from application success or classifier verdict.
function captureErrors(record, report) {
  const c = record.captures.find((x) => /-capture$/.test(x.name)),
    errors = [];
  if (!c) return ["outer_capture_missing"];
  if (c.final_statistics_complete !== true)
    errors.push("final_capture_statistics_missing_or_partial");
  if (record.capture_drain?.complete !== true)
    errors.push("capture_statistics_drain_incomplete");
  if (record.errors?.length) errors.push("acquisition_exception");
  if (
    !record.quiesce ||
    record.quiesce.process_code !== 0 ||
    record.quiesce.result !== "ok"
  )
    errors.push("proxy_quiesce_incomplete");
  if (
    !Number.isSafeInteger(record.quiesce?.finished_unix_micros) ||
    !Number.isSafeInteger(record.drain_end?.unix_micros) ||
    record.drain_end.unix_micros - record.quiesce.finished_unix_micros < 500000
  )
    errors.push("proxy_drain_under500ms_or_unknown");
  if (record.browser && (record.browser.timeout || record.browser.code !== 0))
    errors.push("browser_lifecycle_incomplete");
  if (
    record.browser &&
    (!record.browser_acquisition_complete ||
      record.browser_teardown?.result !== "exited")
  )
    errors.push("browser_completion_or_teardown_unknown");
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
function makeIndex(records, loadReport, stage = "B1") {
  return {
    schema: 4,
    stage,
    reports: records.map((r) => {
      const id = r.group.group_id,
        report = loadReport(id);
      return {
        group_id: id,
        split: r.group.split,
        path: id + "/windows.json",
        longflow_path: id + "/longflow.json",
        coverage_errors: captureErrors(r, report),
      };
    }),
  };
}
module.exports = { captureErrors, makeIndex };

"use strict";
// Independent, read-only B1 acquisition audit. It never scores or fits models.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const { inspectPCAP, pinLocation } = require("./review-checkpoint.cjs");
const sha = raw => crypto.createHash("sha256").update(raw).digest("hex");

function groupChecks(g, r, o, l, raw, f, freezeSHA) {
  const errors = [];
  if (!isDeepStrictEqual(g, r.group)) errors.push("frozen_assignment_mismatch");
  errors.push(...(r.errors || []).map(e => "collector:" + e));
  const outer = (r.captures || []).filter(c => /-capture$/.test(c.name));
  const c = outer[0];
  if (outer.length !== 1 || !c || c.captured !== raw.packets || c.bytes !== raw.bytes || c.received_by_filter !== raw.packets || c.dropped_by_kernel !== 0 || c.capped || c.forced_cleanup || c.incomplete || c.code !== 0 || c.signal || raw.truncated_packets)
    errors.push("outer_capture_accounting_or_lifecycle");
  if (o.schema !== 4 || o.version !== "g03-observer-v2" || l.schema !== 2 || l.version !== "g03-longflow-v2") errors.push("report_schema_or_version");
  if (o.pcap_sha256 !== raw.sha256 || l.pcap_sha256 !== raw.sha256 || o.counters?.packets !== raw.packets) errors.push("raw_report_binding");
  if (!/^[a-f0-9]{64}$/.test(o.ordering_semantics_sha256 || "") || o.ordering_semantics_sha256 !== l.ordering_semantics_sha256) errors.push("ordering_contract_binding");
  for (const report of [o, l]) {
    const m = report.metadata;
    if (!m || m.freeze_sha256 !== freezeSHA || m.group_id !== g.group_id || m.split !== g.split || m.class !== g.class || m.profile !== g.profile || m.measurement_start_unix_micros !== r.measurement_start?.unix_micros || m.measured_seconds !== 80 || m.prefix_grace_seconds !== 2 || m.capture_cap_bytes !== f.pcap_cap_bytes || !isDeepStrictEqual(m.window_offsets_seconds, f.window_offsets_seconds)) errors.push("report_frozen_metadata");
  }
  if (!o.coverage_complete || !l.source_observer_coverage_complete || l.collector_flow_censored || l.collector_omitted_flow_records) errors.push("reporter_coverage_incomplete");
  for (const name of ["observer_process", "longflow_process"]) if (r[name]?.code !== 0 || r[name]?.signal) errors.push(name + "_failed");
  const start = r.measurement_start?.unix_micros, q = r.quiesce, drain = r.drain_end?.unix_micros, end = r.capture_end?.unix_micros;
  if (![start, q?.started_unix_micros, q?.finished_unix_micros, drain, end, r.capture_start?.unix_micros].every(Number.isSafeInteger) || q.started_unix_micros - start < 82_000_000 || q.finished_unix_micros < q.started_unix_micros || drain - q.finished_unix_micros < 500_000 || end < drain || r.capture_start.unix_micros > start || q.result !== "ok" || q.process_code !== 0) errors.push("VM_horizon_quiesce_or_drain");
  if (g.client_stack === "chrome" && (!r.browser_acquisition_complete || r.browser?.code !== 0 || r.browser?.signal || r.browser_teardown?.result !== "exited" || r.browser_teardown?.signals?.length || r.browser_teardown?.errors?.length)) errors.push("browser_acquisition_or_teardown");
  if (g.class === "belnet") {
    const snap = r.snapshots?.find(s => s.label === "t81000");
    const a = snap?.clock?.unix_micros, b = snap?.snapshot_finished?.unix_micros;
    if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b) || a < start + 80_000_000 || b < a || b >= q?.started_unix_micros) errors.push("native_postprimary_snapshot");
  }
  return errors;
}

function audit(run, freezePath) {
  const inputs = [], read = filename => {
    const raw = fs.readFileSync(filename);
    inputs.push({ path: path.resolve(filename), sha256: sha(raw), bytes: raw.length });
    return raw;
  };
  const frozenRaw = read(freezePath), f = JSON.parse(frozenRaw), freezeSHA = sha(frozenRaw);
  if (f.schema !== "belnet-g03-collector/v2" || f.stage !== "B1" || f.groups?.length !== 71 || f.groups.some(g => g.scope !== "primary" || !["train", "validation"].includes(g.split))) throw Error("R2_B1_71_primary_only_reject_Q_or_test_before_reads");
  const status = JSON.parse(read(path.join(run, "status.json")));
  if (status.stage !== "B1" || status.total !== 71 || status.complete !== status.groups?.length) throw Error("invalid_progress_snapshot");
  const declared = new Map(f.groups.map(g => [g.group_id, g]));
  const completed = new Set();
  for (const g of status.groups) {
    if (!declared.has(g.id) || completed.has(g.id)) throw Error("unknown_or_duplicate_progress_group");
    completed.add(g.id);
  }
  const errors = [], pins = [], groups = [];
  for (const [relative, expected] of Object.entries(f.files_sha256)) {
    const loc = pinLocation(f, relative);
    try {
      const actual = sha(read(loc.filename));
      pins.push({ path: relative, kind: loc.kind, expected, actual, matches: expected === actual });
      if (actual !== expected) errors.push("pin_mismatch:" + relative);
    } catch (e) { errors.push("pin_unreadable:" + relative + ":" + e.message); }
  }
  for (const id of completed) {
    const g = declared.get(id), dir = path.join(run, id);
    try {
      const r = JSON.parse(read(path.join(dir, "result.json")));
      const o = JSON.parse(read(path.join(dir, "windows.json")));
      const l = JSON.parse(read(path.join(dir, "longflow.json")));
      const raw = inspectPCAP(read(path.join(dir, "outer.pcap")));
      const problems = groupChecks(g, r, o, l, raw, f, freezeSHA);
      groups.push({ group_id: id, split: g.split, class: g.class, profile: g.profile, qualified: problems.length === 0, errors: problems, raw, observer_coverage: o.coverage_complete, longflow_coverage: l.source_observer_coverage_complete, flows: o.flows.length, masked_windows: o.windows.filter(w => w.ordering_ambiguous).length, primary_windows: o.windows.filter(w => w.primary).length, observer_issues: [...new Set(o.flows.flatMap(f => f.issues || []))] });
    } catch (e) { groups.push({ group_id: id, qualified: false, errors: ["artifact_read_or_decode:" + e.message] }); }
  }
  const missing = f.groups.filter(g => !completed.has(g.group_id)).map(g => g.group_id);
  const qualified = groups.filter(g => g.qualified).length;
  const auditorSHA = sha(read(__filename));
  return { schema: "g03-R2-acquisition-audit/v1", audited_utc: new Date().toISOString(), auditor_sha256: auditorSHA, master_sha256: freezeSHA, stage: "B1", declared: 71, completed: groups.length, qualified_groups: qualified, calibration_ready: errors.length === 0 && missing.length === 0 && qualified === 71, errors, missing_groups: missing, groups, pins, inputs, limits: ["Completed status snapshot only; later groups may still be running", "No rule/model scoring or fitting; no test vault or test captures read", "Independent raw structure/hash/count and acquisition/source/time checks; TCP/TLS semantic coverage is supplied by pinned reporters", "Native operation proof and auxiliary receiver UDP accounting are separate audits"] };
}
if (require.main === module) {
  const [run, freeze, output] = process.argv.slice(2);
  if (!run || !freeze || !output) throw Error("usage: node review-r2.cjs RUN MASTER NEW_OUTPUT");
  const r = audit(run, freeze);
  fs.writeFileSync(output, JSON.stringify(r, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ completed: r.completed, qualified: r.qualified_groups, declared: r.declared, pins: r.pins.length, errors: r.errors, group_errors: r.groups.filter(g => !g.qualified).map(g => ({ id: g.group_id, errors: g.errors })), calibration_ready: r.calibration_ready }));
  process.exitCode = r.calibration_ready ? 0 : 2;
}
module.exports = { audit, groupChecks };

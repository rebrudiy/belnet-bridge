"use strict";
// Passive acquisition audit; never loads a classifier or private test values.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const { inspectPCAP, pinLocation } = require("./review-checkpoint.cjs");
const sha = b => crypto.createHash("sha256").update(b).digest("hex");
const COVERAGE = "5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810";
const ORDERING = "a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1";
function timeNS(value) {
  if (value == null) return null;
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!m || !Number.isFinite(Date.parse(m[1] + "Z"))) throw Error("invalid_UTC_timestamp");
  return BigInt(Date.parse(m[1] + "Z")) * 1000000n + BigInt((m[2] || "").padEnd(9, "0"));
}
function guardFreeze(f) {
  if (f.schema !== "belnet-g03-collector/v4" || !["Q", "B1"].includes(f.stage)) throw Error("explicit_R4_Q_or_B1_required");
  if (!Array.isArray(f.groups) || f.groups.length !== (f.stage === "Q" ? 3 : 71) || f.groups.some(g => f.stage === "Q" ? g.split !== "development" || g.scope !== "diagnostic" || !/^q-/.test(g.group_id) : !["train", "validation"].includes(g.split) || g.scope !== "primary")) throw Error("test_or_invalid_scope_rejected_before_group_reads");
  if (new Set(f.groups.map(g => g.group_id)).size !== f.groups.length || f.groups.some(g => !/^[a-z0-9-]+$/.test(g.group_id))) throw Error("invalid_group_id");
  if (f.stage === "Q" && f.test_seeds_commitment !== null) throw Error("Q_must_not_reference_test_vault");
  if (!f.files_sha256 || Object.keys(f.files_sha256).length === 0) throw Error("nonempty_source_freeze_required");
}
function inventoryErrors(o, startMicros) {
  const errors = [], start = BigInt(startMicros) * 1000n, end = start + 80000000000n, ids = new Set(), primary = [];
  for (const f of o.flows || []) {
    if (!f.flow_id || ids.has(f.flow_id)) errors.push("invalid_or_duplicate_flow_id"); ids.add(f.flow_id);
    if (typeof f.primary_scope !== "boolean" || !Number.isSafeInteger(f.raw_tcp_payload_bytes_including_retransmits) || f.raw_tcp_payload_bytes_including_retransmits < 0) { errors.push("primary_inventory_fields_missing"); continue; }
    const syn = timeNS(f.syn_utc), closed = timeNS(f.closed_utc), first = timeNS(f.first_tls23_utc);
    if (syn !== null && (syn < end && (closed === null || closed >= start)) !== f.primary_scope) errors.push("flow_scope_lifetime_contradiction");
    if (syn !== null && closed !== null && closed < syn) errors.push("flow_closes_before_SYN");
    if (!f.primary_scope && first !== null && first >= start && first < end) errors.push("primary_TLS_hidden_by_scope");
    if (!f.primary_scope) continue;
    primary.push(f);
    if (syn === null || typeof f.syn_ack_captured !== "boolean") errors.push("primary_handshake_inventory_missing");
    if (f.raw_tcp_payload_bytes_including_retransmits > 0 && !f.syn_ack_captured) errors.push("primary_payload_without_handshake");
  }
  if (o.zero_payload_setup_only) {
    if (!primary.length || !primary.every(f => timeNS(f.syn_utc) !== null && timeNS(f.syn_utc) >= start && timeNS(f.syn_utc) < end && f.raw_tcp_payload_bytes_including_retransmits === 0 && f.first_tls23_utc === null)) errors.push("zero_payload_flag_not_supported_by_primary_inventory");
    const anchor = timeNS(o.group_first_tls23_utc);
    if (anchor !== null && anchor < end) errors.push("primary_TLS_anchor_contradicts_zero_flag");
    const windows = [...(o.group_windows || []), ...(o.windows || [])];
    if (windows.some(w => timeNS(w.window_start_utc) >= start && timeNS(w.window_end_utc) <= end && (w.total_records > 0 || w.events?.length > 0))) errors.push("primary_TLS_window_contradicts_zero_flag");
  }
  return { errors: [...new Set(errors)], primary_flows: primary.length, zero_payload_setup_only: o.zero_payload_setup_only === true };
}
function inspectGroup(r, o, l, raw, g, freeze, freezeSHA) {
  const errors = [], need = (ok, name) => { if (!ok) errors.push(name); }, pcap = inspectPCAP(raw);
  need(isDeepStrictEqual(r.group, g), "frozen_assignment_mismatch");
  need(Array.isArray(r.errors) && r.errors.length === 0, "collector_exception");
  const captures = (r.captures || []).filter(c => /-capture$/.test(c.name)), c = captures[0];
  need(captures.length === 1, "outer_capture_count");
  need(c && c.code === 0 && !c.signal && !c.capped && !c.forced_cleanup && !c.incomplete && c.dropped_by_kernel === 0 && c.captured === pcap.packets && c.received_by_filter === pcap.packets && c.bytes === pcap.bytes && pcap.bytes < freeze.pcap_cap_bytes && pcap.truncated_packets === 0, "raw_capture_accounting_or_lifecycle");
  const frontier = c?.final_statistics_frontier, finalText = typeof frontier === "number" ? c.stderr?.slice(frontier) || "" : "";
  const final = /(?:^|\n)(\d+) packets? captured\n(\d+) packets? received by filter\n(\d+) packets? dropped by kernel\n?$/.exec(finalText);
  need(c?.final_statistics_complete === true && Number.isSafeInteger(frontier) && frontier > 0 && frontier < c.stderr.length && final && +final[1] === pcap.packets && +final[2] === pcap.packets && +final[3] === 0, "fresh_final_statistics_missing_or_mismatched");
  need(c?.capture_mode === freeze.capture_mode && c?.capture_buffer_kib === freeze.capture_buffer_kib, "capture_sensor_mismatch");
  const drain = r.capture_drain, samples = drain?.snapshots?.slice(-2) || [];
  need(drain?.complete === true && drain.budget_ms === 2500 && drain.elapsed_ms <= 2500 && samples.length === 2 && samples.every(s => s.captured === pcap.packets && s.received_by_filter === s.captured && s.dropped_by_kernel === 0), "two_healthy_live_statistics_required");
  need(samples.length === 2 && Date.parse(samples[1].observed_host_utc) - Date.parse(samples[0].observed_host_utc) >= 100 && samples.every(s => Date.parse(s.observed_host_utc) <= Date.parse(c?.stop_statistics_frontier_host_utc)), "statistics_stability_or_epoch");
  need(o.schema === 5 && o.version === "g03-observer-v4" && l.schema === 3 && l.version === "g03-longflow-v4", "reporter_ABI");
  need(o.pcap_sha256 === pcap.sha256 && l.pcap_sha256 === pcap.sha256 && o.counters?.packets === pcap.packets, "reporter_raw_binding");
  need(o.coverage_semantics_sha256 === COVERAGE && l.coverage_semantics_sha256 === COVERAGE && o.ordering_semantics_sha256 === ORDERING && l.ordering_semantics_sha256 === ORDERING, "reporter_contract_SHA");
  for (const report of [o, l]) need(report.metadata?.freeze_sha256 === freezeSHA && report.metadata?.group_id === g.group_id && report.metadata?.split === g.split && report.metadata?.measurement_start_unix_micros === r.measurement_start?.unix_micros, "reporter_metadata_binding");
  need(o.coverage_complete === true && l.source_observer_coverage_complete === true && !l.collector_flow_censored && !l.collector_omitted_flow_records, "reporter_coverage_unknown");
  for (const process of ["observer_process", "longflow_process"]) need(r[process]?.code === 0 && !r[process]?.signal, process + "_failed");
  const begin = r.measurement_start?.unix_micros, q = r.quiesce, drainEnd = r.drain_end?.unix_micros, end = r.capture_end?.unix_micros;
  need([begin, q?.started_unix_micros, q?.finished_unix_micros, drainEnd, end, r.capture_start?.unix_micros].every(Number.isSafeInteger) && q.started_unix_micros - begin >= 82000000 && q.finished_unix_micros >= q.started_unix_micros && drainEnd - q.finished_unix_micros >= 500000 && end >= drainEnd && r.capture_start.unix_micros <= begin && q.process_code === 0 && q.result === "ok", "VM_horizon_quiesce_drain");
  let inventory = null;
  if (Number.isSafeInteger(begin)) { inventory = inventoryErrors(o, begin); errors.push(...inventory.errors); }
  if (g.client_stack === "chrome") need(r.browser_acquisition_complete === true && r.browser?.code === 0 && !r.browser?.signal && !r.browser?.timeout && r.browser_teardown?.result === "exited" && !r.browser_teardown?.signals?.length && !r.browser_teardown?.errors?.length, "browser_acquisition_or_teardown");
  if (g.class === "belnet") {
    const s = r.snapshots?.find(s => s.label === "t81000");
    need(s && Number.isSafeInteger(s.clock?.unix_micros) && Number.isSafeInteger(s.snapshot_finished?.unix_micros) && s.clock.unix_micros >= begin + 80000000 && s.snapshot_finished.unix_micros >= s.clock.unix_micros && s.snapshot_finished.unix_micros < q?.started_unix_micros, "postprimary_native_snapshot");
  }
  return { group_id: g.group_id, acquisition_qualified: errors.length === 0, errors: [...new Set(errors)], pcap, primary_flows: inventory?.primary_flows ?? null, zero_payload_setup_only: inventory?.zero_payload_setup_only ?? null, coverage_complete: o.coverage_complete, drain_ms: drain?.elapsed_ms, scope: "Acquisition only; not an application or detector verdict" };
}
function audit(directory, freezePath) {
  const inputs = [], read = file => { const raw = fs.readFileSync(file); inputs.push({ path: path.resolve(file), sha256: sha(raw), bytes: raw.length }); return raw; };
  const frozenRaw = read(freezePath), freeze = JSON.parse(frozenRaw), freezeSHA = sha(frozenRaw);
  guardFreeze(freeze); // Must precede every group/index read.
  const errors = [], pins = [], groups = [];
  if (freeze.measured_seconds !== 80 || freeze.capture_seconds !== 82 || freeze.quiesce_drain_micros !== 500000 || freeze.capture_mode !== "buffered" || freeze.capture_buffer_kib !== 16384 || freeze.stats_drain_budget_ms !== 2500 || freeze.stats_stable_ms !== 100) errors.push("frozen_R4_timing_or_selected_sensor_mismatch");
  for (const [relative, expected] of Object.entries(freeze.files_sha256)) {
    try { const loc = pinLocation(freeze, relative), actual = sha(read(loc.filename)); pins.push({ path: relative, kind: loc.kind, matches: actual === expected }); if (actual !== expected) errors.push("pin_mismatch:" + relative); }
    catch (e) { errors.push("pin_read_failure:" + relative + ":" + e.message); }
  }
  for (const g of freeze.groups) {
    const dir = path.join(directory, g.group_id);
    if (!fs.existsSync(path.join(dir, "result.json"))) continue;
    try { groups.push(inspectGroup(...["result.json", "windows.json", "longflow.json"].map(name => JSON.parse(read(path.join(dir, name)))), read(path.join(dir, "outer.pcap")), g, freeze, freezeSHA)); }
    catch (e) { groups.push({ group_id: g.group_id, acquisition_qualified: false, errors: ["unreadable_group:" + e.message] }); }
  }
  const missing = freeze.groups.map(g => g.group_id).filter(id => !groups.some(g => g.group_id === id));
  return { schema: "g03-root-acquisition-review/v4", checked_utc: new Date().toISOString(), stage: freeze.stage, freeze_sha256: freezeSHA, acquisition_qualified: !errors.length && !missing.length && groups.every(g => g.acquisition_qualified), expected_groups: freeze.groups.length, reviewed_groups: groups.length, missing_groups: missing, errors, groups, pins, inputs, auditor_sha256: sha(read(__filename)), private_test_values_read: false, detector_fitting_allowed: false, limitations: ["Passive acquisition audit only; no classifier scoring or fit", "Primary setup-only TCP attempts remain in inventory and abstain", "Equal counters and byte conservation do not prove every aspect of capture losslessness", "Native application proof and real ISP blocking require separate evidence"] };
}
if (require.main === module) {
  const [directory, freeze, output] = process.argv.slice(2); if (!output) throw Error("usage: node review-r4.cjs RUN FREEZE NEW_OUTPUT");
  const result = audit(directory, freeze); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ qualified: result.acquisition_qualified, expected: result.expected_groups, reviewed: result.reviewed_groups, pins: result.pins.length, errors: result.errors, groups: result.groups.map(g => ({ id: g.group_id, qualified: g.acquisition_qualified, errors: g.errors, packets: g.pcap?.packets })) }));
  process.exitCode = result.acquisition_qualified ? 0 : 2;
}
module.exports = { audit, guardFreeze, inspectGroup, inventoryErrors, timeNS };

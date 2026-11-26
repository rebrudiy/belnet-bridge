"use strict";
// Read-only acquisition audit. Never fits rules or reclassifies frozen reports.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const hash = (raw) => crypto.createHash("sha256").update(raw).digest("hex");
function pinLocation(freeze, relative) {
  if (path.isAbsolute(relative)) return { filename: relative, kind: "current_external_pin" };
  const archiveRoot = path.resolve(freeze.source_archive);
  const archived = path.resolve(archiveRoot, relative);
  if (!archived.startsWith(archiveRoot + path.sep)) throw new Error("archive_pin_path_escape");
  // The frozen collector archives textual sources, but pins ELF/app files in place.
  if (/\.(?:cjs|sh|go|mod|sum|md|json|log)$/.test(relative))
    return { filename: archived, kind: "archived_source" };
  return { filename: path.resolve(__dirname, "../..", relative), kind: "current_binary_pin" };
}

function inspectPCAP(raw) {
  if (raw.length < 24) throw new Error("short_pcap_header");
  const magic = raw.subarray(0, 4).toString("hex");
  const little = ["d4c3b2a1", "4d3cb2a1"].includes(magic);
  if (!little && !["a1b2c3d4", "a1b23c4d"].includes(magic))
    throw new Error("unsupported_pcap_magic");
  const uint = (at) => little ? raw.readUInt32LE(at) : raw.readUInt32BE(at);
  const snaplen = uint(16);
  let at = 24, packets = 0, truncated = 0;
  while (at < raw.length) {
    if (raw.length - at < 16) throw new Error("partial_packet_header");
    const saved = uint(at + 8), original = uint(at + 12);
    if (saved > snaplen || saved > original) throw new Error("invalid_packet_lengths");
    if (saved > raw.length - at - 16) throw new Error("partial_packet_body");
    if (saved !== original) truncated++;
    packets++;
    at += 16 + saved;
  }
  return { packets, truncated_packets: truncated, bytes: raw.length, sha256: hash(raw) };
}

function inspectGroup(record, report, pcap, frozen, freezeSHA) {
  const errors = [], id = frozen.group_id;
  if (!isDeepStrictEqual(record.group, frozen)) errors.push("frozen_assignment_mismatch");
  errors.push(...(record.errors || []).map((e) => "collector: " + e));
  const outer = (record.captures || []).filter((c) => /-capture$/.test(c.name));
  const c = outer[0];
  if (outer.length !== 1) errors.push("outer_capture_count");
  if (c) {
    if (c.capped || c.forced_cleanup || c.incomplete || c.code !== 0 || c.signal)
      errors.push("outer_capture_lifecycle_or_cap");
    if (!Number.isInteger(c.captured) || !Number.isInteger(c.received_by_filter) || !Number.isInteger(c.dropped_by_kernel))
      errors.push("outer_capture_counters_missing");
    else {
      if (c.captured !== c.received_by_filter) errors.push("received_vs_saved_unknown");
      if (c.dropped_by_kernel !== 0) errors.push("kernel_drops");
    }
    if (pcap && (pcap.packets !== c.captured || pcap.bytes !== c.bytes)) errors.push("raw_capture_counter_or_size_mismatch");
  }
  if (!pcap) errors.push("raw_pcap_unreadable");
  else if (pcap.truncated_packets) errors.push("snaplen_truncated_packets");
  if (!report) errors.push("observer_report_missing");
  else {
    if (report.metadata?.group_id !== id || report.metadata?.split !== frozen.split) errors.push("observer_assignment_mismatch");
    if (freezeSHA && report.metadata?.freeze_sha256 !== freezeSHA) errors.push("observer_freeze_binding_mismatch");
    if (report.schema !== 3 || report.version !== "g03-observer-v1") errors.push("observer_schema_or_version_mismatch");
    if (pcap && (report.pcap_sha256 !== pcap.sha256 || report.counters?.packets !== pcap.packets)) errors.push("observer_raw_binding_mismatch");
    if (!report.coverage_complete) errors.push("frozen_observer_incomplete");
    if (record.observer_process?.code !== 0 || record.observer_process?.signal) errors.push("observer_process_failed");
  }
  if (record.browser && (record.browser.timeout || record.browser.code !== 0 || record.browser.signal)) errors.push("browser_lifecycle_incomplete");
  const begin = record.measurement_start?.unix_micros;
  const finish = record.capture_end?.unix_micros;
  if (!Number.isSafeInteger(begin) || !Number.isSafeInteger(finish) || finish - begin < 82_000_000) errors.push("VM_horizon_not_verified");
  const clocks = report?.clock_diagnostics || {};
  const issues = [...new Set((report?.flows || []).flatMap((f) => f.issues || []))].sort();
  return {
    group_id: id, split: frozen.split, class: frozen.class, profile: frozen.profile,
    acquisition_qualified: errors.length === 0, errors,
    raw: pcap,
    observer_coverage_complete: report?.coverage_complete ?? null,
    observer_issues: issues,
    clock_diagnostics: Object.fromEntries(Object.entries(clocks).filter(([key]) => key !== "samples")),
    browser_timeout: record.browser?.timeout ?? false,
    workloads: (record.workloads || []).map((w) => ({ label: w.label, code: w.code, signal: w.signal, completed_duration: w.data?.workload?.completed_duration ?? null, rpc_verified: w.data?.workload?.rpc_verified ?? null })),
    limits: ["Acquisition qualification only; no DPI decision or native payload attribution", "Frozen strict observer flags remain unchanged", "Equal packet counters do not prove an absence of all capture loss"],
  };
}

function audit(runDir, freezePath) {
  const inputs = [], read = (filename) => {
    const raw = fs.readFileSync(filename);
    inputs.push({ path: path.resolve(filename), bytes: raw.length, sha256: hash(raw) });
    return raw;
  };
  const freezeRaw = read(freezePath), freeze = JSON.parse(freezeRaw), freezeSHA = hash(freezeRaw);
  if (freeze.stage !== "B1") throw new Error("development_B1_only");
  if (freeze.schema !== "belnet-g03-collector/v1" || freeze.measured_seconds !== 80 || freeze.capture_seconds !== 82 || !Array.isArray(freeze.groups) || freeze.groups.length === 0 || !freeze.files_sha256 || Object.keys(freeze.files_sha256).length === 0)
    throw new Error("nonempty_frozen_G03_acquisition_required");
  if (freeze.groups.some((g) => !["train", "validation"].includes(g.split))) throw new Error("test_references_rejected_before_group_reads");
  if (new Set(freeze.groups.map((g) => g.group_id)).size !== freeze.groups.length) throw new Error("duplicate_frozen_group");
  const errors = [], pins = [];
  for (const [relative, expected] of Object.entries(freeze.files_sha256)) {
    const location = pinLocation(freeze, relative);
    try {
      const actual = hash(read(location.filename));
      pins.push({ path: relative, kind: location.kind, expected, actual, matches: actual === expected });
      if (actual !== expected) errors.push("frozen_source_pin_mismatch: " + relative);
    } catch (e) { errors.push("frozen_source_unreadable: " + relative + ": " + e.message); }
  }
  const groups = [], missing = [], failures = [];
  for (const g of freeze.groups) {
    if (!/^[a-z0-9-]+$/.test(g.group_id)) throw new Error("unsafe_group_id");
    const dir = path.join(runDir, g.group_id), result = path.join(dir, "result.json");
    if (!fs.existsSync(result)) { missing.push(g.group_id); continue; }
    try {
      const record = JSON.parse(read(result));
      let report = null, pcap = null;
      try { report = JSON.parse(read(path.join(dir, "windows.json"))); } catch (e) { failures.push({ group_id: g.group_id, artifact: "windows.json", error: e.message }); }
      try { pcap = inspectPCAP(read(path.join(dir, "outer.pcap"))); } catch (e) { failures.push({ group_id: g.group_id, artifact: "outer.pcap", error: e.message }); }
      groups.push(inspectGroup(record, report, pcap, g, freezeSHA));
    } catch (e) { failures.push({ group_id: g.group_id, artifact: "result.json", error: e.message }); }
  }
  const qualified = groups.filter((g) => g.acquisition_qualified).length;
  const auditorSHA = hash(read(__filename));
  return {
    schema: "belnet-g03-checkpoint-audit/v1", audited_at: new Date().toISOString(), stage: freeze.stage,
    auditor_sha256: auditorSHA,
    declared_groups: freeze.groups.length, completed_result_files: groups.length,
    missing_groups: missing, acquisition_qualified_groups: qualified,
    calibration_ready: errors.length === 0 && failures.length === 0 && missing.length === 0 && qualified === freeze.groups.length,
    errors, failures, pins, groups, inputs,
    limits: ["Read-only audit of a possibly partial development acquisition", "No rule fitting, policy choice, FPR estimate, stealth or ISP bypass claim", "Does not inspect sealed test seeds or test captures"],
  };
}

if (require.main === module) {
  const [runDir, freezePath, output] = process.argv.slice(2);
  if (!runDir || !freezePath) throw new Error("usage: node review-checkpoint.cjs RUN_DIR FREEZE_JSON [OUTPUT_JSON]");
  const result = audit(runDir, freezePath), raw = JSON.stringify(result, null, 2) + "\n";
  if (output) fs.writeFileSync(output, raw, { mode: 0o600 });
  else process.stdout.write(raw);
  if (output) console.log(JSON.stringify({ completed: result.completed_result_files, qualified: result.acquisition_qualified_groups, declared: result.declared_groups, calibration_ready: result.calibration_ready, errors: result.errors.length, artifact_failures: result.failures.length }));
  process.exitCode = result.calibration_ready ? 0 : 2;
}
module.exports = { inspectPCAP, inspectGroup, audit, pinLocation };

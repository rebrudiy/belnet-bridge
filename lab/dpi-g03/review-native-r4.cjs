"use strict";
// Explicit frozen R4 development scopes only. Reuses the tested passive joins.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const native = require("./review-native.cjs"), { guardFreeze } = require("./review-r4.cjs");
const hash = b => crypto.createHash("sha256").update(b).digest("hex");
function audit(directory, freezePath) {
  const inputs = {}, read = filename => { const raw = fs.readFileSync(filename); inputs[path.resolve(filename)] = hash(raw); return raw; };
  const freezeRaw = read(freezePath), frozen = JSON.parse(freezeRaw); guardFreeze(frozen);
  const selected = frozen.groups.filter(g => g.class === "belnet" && g.stratum === "native"), groups = [], missing = [];
  const service = path.join(directory, "bb-g03-service.log"), rows = [], serviceErrors = [];
  read(service).toString().split("\n").forEach((line, i) => { if (!line.trim()) return; try { rows.push(JSON.parse(line)); } catch (e) { serviceErrors.push({ line: i + 1, message: e.message }); } });
  for (const g of selected) {
    const dir = path.join(directory, g.group_id), filename = path.join(dir, "result.json");
    if (!fs.existsSync(filename)) { missing.push(g.group_id); continue; }
    const r = JSON.parse(read(filename)); if (!isDeepStrictEqual(g, r.group)) throw Error("native_group_assignment_mismatch");
    const start = r.measurement_start?.unix_micros, end = start + 80000000;
    if (!Number.isSafeInteger(start)) throw Error("native_primary_clock_missing");
    const operations = native.expectedOperations(g).map(e => native.joinOperation(e, r.workloads.find(w => w.label === e.label), rows, start, end));
    const pids = [1, 2].map(n => Number(read(path.join(dir, "adapter" + n + ".pid")).toString().trim()));
    const processes = native.auditProcesses(r.snapshots, pids), streams = native.auditStreams(r.snapshots);
    const firewall = r.snapshots.map(s => ({ label: s.label, command_ok: s.native_firewall?.code === 0, ...native.parseFirewall(s.native_firewall?.stdout || "") }));
    const leak = read(path.join(dir, "native-raw-udp.pcap")), leakPackets = native.pcapRecordCount(leak);
    const logs = native.censusLogs(read(path.join(dir, "belnet.log")).toString(), start, end);
    const metadata = JSON.parse(read(path.join(dir, "observer-meta.json")));
    if (metadata.freeze_sha256 !== hash(freezeRaw)) throw Error("native_proof_freeze_binding_mismatch");
    read(path.join(dir, "outer.pcap"));
    groups.push({ group_id: g.group_id, family: g.family, operations, processes, streams, firewall, raw_UDP_leak: { pcap_bytes: leak.length, saved_packets: leakPackets }, udp_primary_windows: native.udpWindowCounts(r.snapshots, start), native_log_census: logs, capture_metadata: r.captures.map(native.captureSummary) });
  }
  const operations = groups.flatMap(g => g.operations), nonceCounts = new Map();
  for (const o of operations) nonceCounts.set(o.expected.nonce, (nonceCounts.get(o.expected.nonce) || 0) + 1);
  for (const o of operations) {
    o.expected_nonce_reused = nonceCounts.get(o.expected.nonce) !== 1;
    if (o.expected_nonce_reused) { o.unique_nonce_count_and_metadata_proof = false; o.strict_both_endpoints_duration_complete = false; }
  }
  read(__filename); read(require.resolve("./review-native.cjs")); read(require.resolve("./review-r4.cjs"));
  return { schema: "g03-native-development-review/v4", stage: frozen.stage, freeze_sha256: hash(freezeRaw), read_only: true, private_test_values_read: false, expected_native_groups: selected.length, reviewed_native_groups: groups.length, missing_groups: missing, service_parse_errors: serviceErrors, summary: { attempts: operations.length, nonce_exact_count_metadata_proofs: operations.filter(o => o.unique_nonce_count_and_metadata_proof).length, both_endpoint_duration_complete_proofs: operations.filter(o => o.strict_both_endpoints_duration_complete).length, initial_failures: operations.filter(o => o.label === "initial" && o.client_exit_code !== 0).length, all_nonces_unique: operations.every(o => !o.expected_nonce_reused), sampled_process_and_stream_continuity: groups.length > 0 && groups.every(g => g.processes.continuous_at_samples && g.streams.continuous_at_samples), raw_UDP_leak_packets: groups.reduce((n, g) => n + g.raw_UDP_leak.saved_packets, 0), native_log_counts: Object.fromEntries(Object.keys(groups[0]?.native_log_census.counts || {}).map(k => [k, groups.reduce((n, g) => n + g.native_log_census.counts[k].total, 0)])) }, groups, input_sha256: inputs, limits: ["Does not score a classifier, upgrade capture metadata or prove ISP bypass", "Every failed attempt retained; log notifications are not independent user disconnects", "Native process/SID/tuple continuity verified only at recorded checkpoints", "Pattern/SHA fields are instrumented application reports; absent raw application bodies are not rehashed"] };
}
if (require.main === module) {
  const [directory, freeze, output] = process.argv.slice(2); if (!output) throw Error("usage: node review-native-r4.cjs RUN FREEZE NEW_OUTPUT");
  const result = audit(directory, freeze); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ groups: result.reviewed_native_groups, missing: result.missing_groups, service_errors: result.service_parse_errors, summary: result.summary }));
}
module.exports = { audit };

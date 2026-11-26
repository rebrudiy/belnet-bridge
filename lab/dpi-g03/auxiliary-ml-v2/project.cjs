"use strict";
// B1 projection only. No index, group/report, vault or classifier reads.
// CLI: node project.cjs --master FILE --audit FILE --tooling FILE --out-dir NEW
//      [--authorize-read --authorize-fit] [--binary-key auxiliary|auxiliary-linux-arm64]
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const ROOT = path.resolve(__dirname, "../../..");
const COVERAGE = "5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810";
const ORDERING = "a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1";
const FEATURES = "61f9f7d79b0a0e38f2e41bc0d416198e471f90a5d39af194a653d395dd80239b";
const LIBRARY = "5720ddfe94cc8dbf67217010c0f460fe65331a401444d92d11f96fee25b3e954";
const CONFIG = { seed: 2026111907, trees: 128, depth: 8, fpr_budget: 0.05 };
const OFFSETS = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78];
const OBSERVER_MANIFEST = "lab/dpi-g03/observer-v4/tooling/TOOLING.json";
const hash = raw => crypto.createHash("sha256").update(raw).digest("hex");
const encode = value => Buffer.from(JSON.stringify(value, null, 2) + "\n");
const hex = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const empty = value => Array.isArray(value) && value.length === 0;
function need(ok, message) { if (!ok) throw Error(message); }
function utc(value) {
  need(typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)), "valid_UTC_required");
  return Date.parse(value);
}
function build({ masterRaw, auditRaw, toolingRaw, observerRaw, auxiliaryBinaryRaw, auditorSHA, binaryKey = "auxiliary", now = new Date().toISOString(), readAuthorized = false, fitAuthorized = false }) {
  need(typeof readAuthorized === "boolean" && typeof fitAuthorized === "boolean" && (!fitAuthorized || readAuthorized), "fit_authorization_requires_read");
  const master = JSON.parse(masterRaw), audit = JSON.parse(auditRaw), tooling = JSON.parse(toolingRaw), observer = JSON.parse(observerRaw), collectorSHA = hash(masterRaw);
  need(master.schema === "belnet-g03-collector/v4" && master.stage === "B1", "completed_R4_B1_only_no_Q_or_test");
  need(master.measured_seconds === 80 && master.capture_seconds === 82 && master.prefix_grace_seconds === 2 && master.pcap_cap_bytes === 268435456 && isDeepStrictEqual(master.window_offsets_seconds, OFFSETS), "canonical_80s_capture_contract_required");
  need(Array.isArray(master.groups) && master.groups.length === 71, "exact_finished71_required");
  const ids = new Set(), sources = new Map(), keys = ["group_id", "source_workload_id", "scope", "transport", "client_stack", "split", "class", "profile"];
  const groups = master.groups.map(g => {
    need(keys.every(k => typeof g[k] === "string" && g[k].length > 0) && /^[a-z0-9-]+$/.test(g.group_id) && !ids.has(g.group_id), "unique_complete_assignment_required");
    need(g.scope === "primary" && ["train", "validation"].includes(g.split) && ["benign", "belnet"].includes(g.class), "test_Q_diagnostic_rejected");
    need(g.transport === (g.class === "benign" ? "ordinary-tls" : "reality"), "primary_transport_class_mismatch");
    need(!sources.has(g.source_workload_id) || sources.get(g.source_workload_id) === g.split, "paired_source_split_leakage");
    ids.add(g.group_id); sources.set(g.source_workload_id, g.split);
    return Object.fromEntries(keys.map(k => [k, g[k]]));
  });
  need(audit.schema === "g03-root-acquisition-review/v4" && audit.stage === "B1" && audit.freeze_sha256 === collectorSHA && audit.private_test_values_read === false, "root_audit_exact_master_binding_required");
  need(audit.acquisition_qualified === true && audit.expected_groups === 71 && audit.reviewed_groups === 71 && empty(audit.errors) && empty(audit.missing_groups) && Array.isArray(audit.groups) && audit.groups.length === 71, "complete_qualified71_root_audit_required");
  const audited = new Set();
  for (const g of audit.groups) {
    need(ids.has(g.group_id) && !audited.has(g.group_id) && g.acquisition_qualified === true && empty(g.errors), "all_exact_declared_groups_must_qualify");
    audited.add(g.group_id);
  }
  need(hex(auditorSHA) && audit.auditor_sha256 === auditorSHA, "root_auditor_source_pin_mismatch");
  const pins = master.files_sha256;
  need(pins && Object.keys(pins).length > 0 && Object.values(pins).every(hex) && Array.isArray(audit.pins) && audit.pins.length === Object.keys(pins).length, "complete_collector_pin_census_required");
  const seenPins = new Set();
  for (const pin of audit.pins) {
    need(Object.hasOwn(pins, pin.path) && !seenPins.has(pin.path) && pin.matches === true, "all_collector_source_pins_must_match");
    seenPins.add(pin.path);
  }
  const frozenAt = utc(master.frozen_at), auditAt = utc(audit.checked_utc), issuedAt = utc(now);
  need(auditAt > frozenAt && issuedAt >= auditAt, "release_must_follow_finished_audit");
  need(tooling.schema === 1 && tooling.role === "auxiliary-ml" && tooling.version === "g03-auxiliary-ml-v2" && tooling.feature_count === 80 && tooling.feature_definitions_sha256 === FEATURES && tooling.readonly_library_source?.sha256 === LIBRARY && tooling.ordering_semantics_sha256 === ORDERING && tooling.coverage_semantics_sha256 === COVERAGE && isDeepStrictEqual(tooling.hyperparameters, CONFIG), "predeclared_auxiliary_contract_mismatch");
  need(utc(tooling.created_at) <= frozenAt, "auxiliary_tooling_must_precede_collector_freeze");
  need(["auxiliary", "auxiliary-linux-arm64"].includes(binaryKey) && hex(tooling.binary?.[binaryKey]?.sha256) && hash(auxiliaryBinaryRaw) === tooling.binary[binaryKey].sha256, "auxiliary_binary_pin_mismatch");
  need(observer.schema === 5 && observer.version === "g03-observer-v4" && observer.coverage_semantics_sha256 === COVERAGE && observer.ordering_semantics_sha256 === ORDERING && hex(observer.binary?.observer?.sha256), "observer_v4_contract_mismatch");
  need(pins[OBSERVER_MANIFEST] === hash(observerRaw) && pins[observer.binary.observer.versioned_path] === observer.binary.observer.sha256, "observer_not_pinned_by_collector");
  const release = { schema: 1, role: "auxiliary-data-release", stage: "B1", collector_freeze_sha256: collectorSHA, issued_at: now, acquisition_finished: true, read_authorized: readAuthorized, fit_authorized: fitAuthorized };
  const releaseRaw = encode(release);
  // frozen_at is the original pre-acquisition collector clock. Replacing it
  // with projection-generation time would invalidate every fresh capture.
  const projection = { schema: 1, role: "auxiliary-ml", stage: "B1", frozen_at: master.frozen_at, stage_a_viability: "proceed", collector_freeze_sha256: collectorSHA, observer_sha256: observer.binary.observer.sha256, observer_version: "g03-observer-v4", ordering_semantics_sha256: ORDERING, coverage_semantics_sha256: COVERAGE, auxiliary_binary_sha256: tooling.binary[binaryKey].sha256, feature_definitions_sha256: FEATURES, library_source_sha256: LIBRARY, data_release_path: "data-release.json", data_release_sha256: hash(releaseRaw), measured_seconds: 80, capture_seconds: 82, prefix_grace_seconds: 2, window_offsets_seconds: OFFSETS, window_seconds: 2, capture_cap_bytes: 268435456, group_fpr_budget: 0.05, direct_flow_fpr_budget: 0.05, hyperparameters: CONFIG, groups };
  const projectionRaw = encode(projection);
  return { release, projection, releaseRaw, projectionRaw, bindings: { collector_freeze_sha256: collectorSHA, acquisition_audit_sha256: hash(auditRaw), auxiliary_tooling_sha256: hash(toolingRaw), observer_tooling_sha256: hash(observerRaw), auxiliary_projection_sha256: hash(projectionRaw), data_release_sha256: hash(releaseRaw), read_authorized: readAuthorized, fit_authorized: fitAuthorized, actual_group_or_index_or_vault_files_read: false } };
}
function argumentsFor(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]; need(["--master", "--audit", "--tooling", "--out-dir", "--binary-key", "--authorize-read", "--authorize-fit"].includes(key) && !Object.hasOwn(args, key), "unknown_or_repeated_argument");
    if (key.startsWith("--authorize-")) args[key] = true;
    else { need(typeof argv[i + 1] === "string" && !argv[i + 1].startsWith("--"), "argument_value_required"); args[key] = argv[++i]; }
  }
  for (const key of ["--master", "--audit", "--tooling", "--out-dir"]) need(args[key], "explicit_master_audit_tooling_and_new_output_required");
  return args;
}
function main(argv) {
  const args = argumentsFor(argv), out = path.resolve(args["--out-dir"]);
  need(!fs.existsSync(out), "output_directory_exists_no_overwrite");
  // These are the only inputs: no index/group/vault path is ever opened.
  const masterRaw = fs.readFileSync(args["--master"]), auditRaw = fs.readFileSync(args["--audit"]), toolingRaw = fs.readFileSync(args["--tooling"]);
  const tooling = JSON.parse(toolingRaw), binaryKey = args["--binary-key"] || (process.platform === "linux" ? "auxiliary-linux-arm64" : "auxiliary");
  const binary = tooling.binary?.[binaryKey]; need(binary?.versioned_path, "auxiliary_binary_descriptor_required");
  const result = build({ masterRaw, auditRaw, toolingRaw, observerRaw: fs.readFileSync(path.join(ROOT, OBSERVER_MANIFEST)), auxiliaryBinaryRaw: fs.readFileSync(path.resolve(ROOT, binary.versioned_path)), auditorSHA: hash(fs.readFileSync(path.join(ROOT, "lab/dpi-g03/review-r4.cjs"))), binaryKey, readAuthorized: args["--authorize-read"] === true, fitAuthorized: args["--authorize-fit"] === true });
  fs.mkdirSync(path.dirname(out), { recursive: true }); fs.mkdirSync(out, { mode: 0o700 });
  try {
    fs.writeFileSync(path.join(out, "data-release.json"), result.releaseRaw, { flag: "wx", mode: 0o600 });
    fs.writeFileSync(path.join(out, "auxiliary-b1.json"), result.projectionRaw, { flag: "wx", mode: 0o600 });
  } catch (error) { error.message = "projection_write_incomplete_no_fit: " + error.message; throw error; }
  return { directory: out, ...result.bindings, projector_sha256: hash(fs.readFileSync(__filename)) };
}
if (require.main === module) { try { console.log(JSON.stringify(main(process.argv.slice(2)))); } catch (error) { console.error(error.message); process.exitCode = 1; } }
module.exports = { build, main, argumentsFor };

'use strict';
// Offline metadata projection only. Never reads an index/report/PCAP/vault or runs fit.
// CLI: --master FILE --audit FILE --tooling FILE --out-dir NEW [--authorize-read --authorize-fit]
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const ROOT = path.resolve(__dirname, '../../..');
const CONTRACT = 'r4-worst-case-benign-fp-v1';
const COVERAGE =
  '5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810';
const ORDERING =
  'a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1';
const LONGFLOW =
  '9d866dd631df3601630ee0f3ce0c00383f50a46194bca44cd88349bffade864e';
const WINDOW =
  'fe5a3d12c958b1d410aa4af5e75fa1fa24fbcc86bc41091ca62e50be6458bd87';
const ENGINE =
  'c5adef946409fa235fad8248602dac4054b54bf1f9f2f9a41d7c687623c24de0';
const OFFSETS = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78];
const OBSERVER_PATH = 'lab/dpi-g03/observer-v4/tooling/TOOLING.json';
const LONGFLOW_PATH = 'lab/dpi-g03/longflow-v4/tooling/TOOLING.json';
const AUDITOR_PATH = 'lab/dpi-g03/review-analysis-r4.cjs';
const KEYS = [
  'group_id',
  'source_workload_id',
  'scope',
  'transport',
  'client_stack',
  'split',
  'class',
  'profile'
];
const hash = (raw) => crypto.createHash('sha256').update(raw).digest('hex');
const encode = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const hex = (value) =>
  typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function need(ok, message) {
  if (!ok) throw Error(message);
}
function utc(value) {
  need(
    typeof value === 'string' &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) &&
      Number.isFinite(Date.parse(value)),
    'valid_UTC_required'
  );
  return Date.parse(value);
}
function safePath(value) {
  need(
    typeof value === 'string' &&
      value.length > 0 &&
      !/vault|sealed[-_]|(?:^|[\\/])b-test-|(?:^|[\\/])b2(?:[\\/]|$)|(?:^|[\\/])q-(?:r|20)/i.test(
        value
      ),
    'test_Q_vault_path_forbidden'
  );
  return value;
}
function pinned(ref) {
  need(
    ref && path.isAbsolute(safePath(ref.path)) && hex(ref.sha256),
    'absolute_pinned_reference_required'
  );
}

// This preflight is pure and precedes all tooling/binary/index/report IO.
function preflight({
  masterRaw,
  auditRaw,
  masterPath,
  auditorSHA,
  now = new Date().toISOString()
}) {
  const master = JSON.parse(masterRaw),
    audit = JSON.parse(auditRaw),
    collectorSHA = hash(masterRaw);
  need(path.isAbsolute(safePath(masterPath)), 'absolute_master_required');
  need(
    master.schema === 'belnet-g03-collector/v4' && master.stage === 'B1',
    'completed_B1_only_no_Q_or_test'
  );
  need(
    master.measured_seconds === 80 &&
      master.capture_seconds === 82 &&
      master.prefix_grace_seconds === 2 &&
      master.pcap_cap_bytes === 268435456 &&
      isDeepStrictEqual(master.window_offsets_seconds, OFFSETS),
    'canonical_80s_82s_contract_required'
  );
  need(
    Array.isArray(master.groups) && master.groups.length === 71,
    'exact71_required'
  );
  const ids = new Set(),
    sources = new Map();
  const groups = master.groups.map((g) => {
    need(
      KEYS.every((k) => typeof g[k] === 'string' && g[k].length > 0) &&
        /^[a-z0-9-]+$/.test(g.group_id) &&
        !ids.has(g.group_id),
      'unique_complete_assignment_required'
    );
    need(
      g.scope === 'primary' &&
        ['train', 'validation'].includes(g.split) &&
        ['benign', 'belnet'].includes(g.class) &&
        !/^q-|^b-test-/.test(g.group_id),
      'test_Q_diagnostic_rejected'
    );
    need(
      g.transport === (g.class === 'benign' ? 'ordinary-tls' : 'reality'),
      'primary_transport_class_mismatch'
    );
    need(
      !sources.has(g.source_workload_id) ||
        sources.get(g.source_workload_id) === g.split,
      'source_workload_split_leakage'
    );
    ids.add(g.group_id);
    sources.set(g.source_workload_id, g.split);
    return {
      ...Object.fromEntries(KEYS.map((k) => [k, g[k]])),
      collector_freeze_sha256: collectorSHA
    };
  });
  need(
    audit.schema === 'g03-root-conservative-analysis-release/v1' &&
      audit.stage === 'B1' &&
      audit.analysis_contract === CONTRACT &&
      audit.analysis_input_allowed === true &&
      audit.raw_acquisition_complete === true &&
      audit.terminal_completed === true &&
      audit.expected_groups === 71 &&
      audit.observed_groups === 71,
    'terminal_independent71_analysis_audit_required'
  );
  need(
    audit.private_test_values_read === false &&
      audit.classifier_fitting_performed === false &&
      audit.certified_policy_issued === false,
    'input_release_is_not_fit_or_certificate'
  );
  pinned(audit.collector_freeze);
  pinned(audit.observer_index);
  pinned(audit.strict_audit);
  need(
    audit.collector_freeze.path === masterPath &&
      audit.collector_freeze.sha256 === collectorSHA &&
      audit.frozen_collector_sha256 === collectorSHA,
    'audit_exact_master_binding_required'
  );
  need(
    hex(auditorSHA) &&
      audit.auditor_sha256 === auditorSHA &&
      hex(audit.strict_audit.auditor_sha256),
    'independent_auditor_source_pin_mismatch'
  );
  need(
    master.prepared &&
      audit.prepared?.path === path.resolve(master.prepared.path) &&
      audit.prepared.sha256 === master.prepared.sha256 &&
      audit.prepared.assets_checked > 0 &&
      audit.prepared.binaries_checked >= 2 &&
      audit.input_sha256?.[audit.prepared.path] === master.prepared.sha256,
    'independent_preparation_verification_required'
  );
  need(
    audit.input_sha256?.[masterPath] === collectorSHA &&
      audit.input_sha256?.[audit.observer_index.path] ===
        audit.observer_index.sha256 &&
      audit.input_sha256?.[audit.strict_audit.path] ===
        audit.strict_audit.sha256,
    'audited_input_hash_bindings_required'
  );
  need(
    Array.isArray(audit.groups) &&
      audit.groups.length === 71 &&
      new Set(audit.groups.map((g) => g.group_id)).size === 71,
    'exact_audited71_required'
  );
  for (const g of audit.groups) {
    need(
      ids.has(g.group_id) &&
        g.raw_acquisition_qualified === true &&
        typeof g.strict_acquisition_qualified === 'boolean' &&
        typeof g.semantic_unknown === 'boolean' &&
        typeof g.semantic_coverage_complete === 'boolean' &&
        g.semantic_unknown === !g.semantic_coverage_complete,
      'raw_acquisition_must_qualify_semantic_unknown_retained'
    );
    need(
      Array.isArray(g.primary_flow_inventory) &&
        g.primary_flow_inventory.length > 0 &&
        g.primary_flow_inventory.every(
          (id) => typeof id === 'string' && id.length > 0
        ) &&
        new Set(g.primary_flow_inventory).size ===
          g.primary_flow_inventory.length,
      'bounded_primary_inventory_required'
    );
  }
  const unknown = audit.groups
    .filter((g) => g.semantic_unknown)
    .map((g) => g.group_id)
    .sort();
  need(
    Array.isArray(audit.semantic_unknown_groups) &&
      isDeepStrictEqual([...audit.semantic_unknown_groups].sort(), unknown) &&
      audit.semantic_coverage_complete === (unknown.length === 0),
    'semantic_unknown_census_mismatch'
  );
  const frozenAt = utc(master.frozen_at),
    completedAt = utc(audit.completion_finished_utc),
    auditAt = utc(audit.checked_utc),
    issuedAt = utc(now);
  need(
    completedAt > frozenAt && auditAt >= completedAt && issuedAt >= auditAt,
    'projection_must_follow_terminal_independent_audit'
  );
  need(
    master.files_sha256 &&
      Object.keys(master.files_sha256).length > 0 &&
      Object.values(master.files_sha256).every(hex),
    'complete_master_source_pins_required'
  );
  return { master, audit, groups, collectorSHA, now, unknown };
}
function executable(raw, sha, label) {
  need(
    Buffer.isBuffer(raw) && hash(raw) === sha,
    label + '_binary_pin_mismatch'
  );
}
function validateTooling(tooling, engineSHA = ENGINE) {
  need(
    tooling.schema === 4 &&
      tooling.version === 'g03-ensemble-v4' &&
      tooling.analysis_contract === CONTRACT &&
      hex(tooling.definitions_sha256) &&
      tooling.window_definitions_sha256 === WINDOW &&
      tooling.longflow_definitions_sha256 === LONGFLOW &&
      tooling.coverage_semantics_sha256 === COVERAGE &&
      tooling.ordering_semantics_sha256 === ORDERING &&
      tooling.score_engine?.sha256 === engineSHA,
    'final_v4_tooling_contract_required'
  );
}
function build(options) {
  const { master, audit, groups, collectorSHA, now, unknown } =
    preflight(options);
  const engineSHA =
    options.syntheticFixture === true ? options.fixtureEngineSHA : ENGINE;
  need(
    hex(engineSHA) &&
      (!options.syntheticFixture ||
        (!options.readAuthorized && !options.fitAuthorized)),
    'synthetic_fixtures_cannot_authorize_data'
  );
  const {
    toolingRaw,
    observerRaw,
    longflowRaw,
    ensembleBinaryRaw,
    engineBinaryRaw,
    longflowBinaryRaw,
    binaryKey = 'ensemble',
    readAuthorized = false,
    fitAuthorized = false
  } = options;
  need(
    typeof readAuthorized === 'boolean' &&
      typeof fitAuthorized === 'boolean' &&
      (!fitAuthorized || readAuthorized),
    'fit_authorization_requires_explicit_read'
  );
  const tooling = JSON.parse(toolingRaw),
    observer = JSON.parse(observerRaw),
    longflow = JSON.parse(longflowRaw);
  validateTooling(tooling, engineSHA);
  need(
    tooling.analysis_contract_document?.path === 'lab/dpi-g03/ANALYSIS-R4.md' &&
      hex(tooling.analysis_contract_document.sha256) &&
      hash(options.analysisContractRaw) ===
        tooling.analysis_contract_document.sha256,
    'analysis_contract_document_pin_mismatch'
  );
  // The classifier is a declared post-hoc analysis; it need not predate B1.
  need(utc(tooling.created_at) <= utc(now), 'tooling_cannot_be_from_future');
  need(
    observer.schema === 5 &&
      observer.version === 'g03-observer-v4' &&
      observer.coverage_semantics_sha256 === COVERAGE &&
      observer.ordering_semantics_sha256 === ORDERING &&
      longflow.schema === 3 &&
      longflow.version === 'g03-longflow-v4' &&
      longflow.feature_definitions_sha256 === LONGFLOW &&
      longflow.coverage_semantics_sha256 === COVERAGE &&
      longflow.ordering_semantics_sha256 === ORDERING,
    'pinned_v4_observer_longflow_contract_required'
  );
  need(
    utc(observer.created_at) <= utc(master.frozen_at) &&
      utc(longflow.created_at) <= utc(master.frozen_at),
    'observation_tools_must_precede_capture'
  );
  need(
    tooling.observer_descriptor_sha256 === hash(observerRaw) &&
      tooling.longflow_descriptor_sha256 === hash(longflowRaw) &&
      master.files_sha256[OBSERVER_PATH] === hash(observerRaw) &&
      master.files_sha256[LONGFLOW_PATH] === hash(longflowRaw),
    'observation_descriptors_not_pinned_before_capture'
  );
  need(
    ['ensemble', 'ensemble-linux-arm64'].includes(binaryKey),
    'explicit_supported_binary_required'
  );
  const ensemble = tooling.binary?.[binaryKey],
    extractor =
      longflow.binary?.[
        binaryKey === 'ensemble' ? 'longflow' : 'longflow-linux-arm64'
      ];
  need(
    hex(ensemble?.sha256) &&
      hex(extractor?.sha256) &&
      hex(observer.binary?.observer?.sha256),
    'versioned_binary_descriptors_required'
  );
  need(
    master.files_sha256[observer.binary.observer.versioned_path] ===
      observer.binary.observer.sha256 &&
      master.files_sha256[extractor.versioned_path] === extractor.sha256 &&
      master.files_sha256[tooling.score_engine.versioned_path] === engineSHA,
    'observation_and_engine_binaries_not_pinned_before_capture'
  );
  executable(ensembleBinaryRaw, ensemble.sha256, 'ensemble');
  executable(engineBinaryRaw, engineSHA, 'engine');
  executable(longflowBinaryRaw, extractor.sha256, 'longflow');
  const synthetic = options.syntheticFixture === true;
  const release = {
    synthetic_fixture: synthetic,
    schema: 1,
    role: 'classical-data-release',
    stage: 'B1',
    analysis_contract: CONTRACT,
    collector_freeze_sha256: collectorSHA,
    independent_analysis_audit_sha256: hash(options.auditRaw),
    issued_at: now,
    acquisition_finished: true,
    semantic_unknown_groups: unknown,
    read_authorized: readAuthorized,
    fit_authorized: fitAuthorized,
    certified_policy_issued: false
  };
  const releaseRaw = encode(release);
  const projection = {
    synthetic_fixture: synthetic,
    schema: 4,
    stage: 'B1',
    analysis_contract: CONTRACT,
    stage_a_viability: 'proceed',
    frozen_at: now,
    collector_freeze_sha256: collectorSHA,
    collectors: [{ path: options.masterPath, sha256: collectorSHA }],
    observer_schema: 5,
    observer_version: 'g03-observer-v4',
    observer_sha256: observer.binary.observer.sha256,
    ordering_semantics_sha256: ORDERING,
    coverage_semantics_sha256: COVERAGE,
    ensemble_binary_sha256: ensemble.sha256,
    score_engine_sha256: engineSHA,
    definitions_sha256: tooling.definitions_sha256,
    window_definitions_sha256: WINDOW,
    longflow_definitions_sha256: LONGFLOW,
    longflow_extractor_sha256: extractor.sha256,
    measured_seconds: 80,
    capture_seconds: 82,
    prefix_grace_seconds: 2,
    window_offsets_seconds: OFFSETS,
    window_seconds: 2,
    cooldown_seconds: 30,
    capture_cap_bytes: 268435456,
    group_fpr_budget: 0.05,
    direct_flow_fpr_budget: 0.05,
    data_release_path: 'data-release.json',
    data_release_sha256: hash(releaseRaw),
    groups
  };
  const descriptor = {
    schema: 'g03-index-union-descriptor/v1',
    stage: 'B1',
    analysis_contract: CONTRACT,
    materialized: false,
    read_authorized: readAuthorized,
    fit_authorized: fitAuthorized,
    input_indexes: [
      { ...audit.observer_index, collector_freeze_sha256: collectorSHA }
    ],
    groups: groups.map((g) => ({
      group_id: g.group_id,
      split: g.split,
      collector_freeze_sha256: collectorSHA
    }))
  };
  return {
    projection,
    release,
    descriptor,
    projectionRaw: encode(projection),
    releaseRaw,
    descriptorRaw: encode(descriptor),
    bindings: {
      synthetic_fixture: synthetic,
      collector_freeze_sha256: collectorSHA,
      independent_analysis_audit_sha256: hash(options.auditRaw),
      ensemble_tooling_sha256: hash(toolingRaw),
      projection_sha256: hash(encode(projection)),
      data_release_sha256: hash(releaseRaw),
      index_union_descriptor_sha256: hash(encode(descriptor)),
      read_authorized: readAuthorized,
      fit_authorized: fitAuthorized,
      semantic_unknown_groups: unknown,
      actual_index_or_report_or_vault_files_read: false,
      classifier_fitting_performed: false,
      certified_policy_issued: false
    }
  };
}
function argumentsFor(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    need(
      [
        '--master',
        '--audit',
        '--tooling',
        '--out-dir',
        '--binary-key',
        '--authorize-read',
        '--authorize-fit'
      ].includes(key) && !Object.hasOwn(args, key),
      'unknown_or_repeated_argument'
    );
    if (key.startsWith('--authorize-')) args[key] = true;
    else {
      need(
        typeof argv[i + 1] === 'string' && !argv[i + 1].startsWith('--'),
        'argument_value_required'
      );
      args[key] = argv[++i];
    }
  }
  for (const key of ['--master', '--audit', '--tooling', '--out-dir'])
    need(args[key], 'explicit_master_audit_tooling_new_output_required');
  return args;
}
function main(argv, io = {}) {
  const read = io.readFileSync || fs.readFileSync,
    exists = io.existsSync || fs.existsSync,
    mkdir = io.mkdirSync || fs.mkdirSync,
    write = io.writeFileSync || fs.writeFileSync,
    root = io.root || ROOT;
  const args = argumentsFor(argv),
    out = path.resolve(safePath(args['--out-dir']));
  need(!exists(out), 'new_output_directory_required_no_overwrite');
  const readSafe = (p) => read(safePath(p));
  const options = {
    masterPath: path.resolve(safePath(args['--master'])),
    masterRaw: readSafe(args['--master']),
    auditRaw: readSafe(args['--audit']),
    auditorSHA: hash(readSafe(path.join(root, AUDITOR_PATH))),
    now: io.now || new Date().toISOString(),
    syntheticFixture: io.syntheticFixture === true,
    fixtureEngineSHA: io.fixtureEngineSHA
  };
  preflight(options); // Nothing beyond metadata and auditor source is read before this gate.
  options.toolingRaw = readSafe(args['--tooling']);
  const tooling = JSON.parse(options.toolingRaw),
    binaryKey = args['--binary-key'] || 'ensemble';
  need(
    ['ensemble', 'ensemble-linux-arm64'].includes(binaryKey),
    'explicit_supported_binary_required'
  );
  validateTooling(
    tooling,
    options.syntheticFixture ? options.fixtureEngineSHA : ENGINE
  );
  const ensemble = tooling.binary?.[binaryKey];
  need(
    ensemble?.versioned_path && tooling.score_engine?.versioned_path,
    'tooling_binary_paths_required'
  );
  need(
    /^lab\/dpi-g03\/ensemble-v4\/tooling\/ensemble-g03-v4-(?:darwin|linux)-arm64-[a-f0-9]{12}$/.test(
      ensemble.versioned_path
    ) &&
      tooling.score_engine.versioned_path ===
        'out/dpi-g03/tooling-defender/classical-existing15-darwin-arm64-c5adef946409',
    'fixed_tooling_binary_paths_required'
  );
  options.observerRaw = readSafe(path.join(root, OBSERVER_PATH));
  options.longflowRaw = readSafe(path.join(root, LONGFLOW_PATH));
  const longflow = JSON.parse(options.longflowRaw),
    extractor =
      longflow.binary?.[
        binaryKey === 'ensemble' ? 'longflow' : 'longflow-linux-arm64'
      ];
  need(extractor?.versioned_path, 'longflow_binary_path_required');
  need(
    /^lab\/dpi-g03\/longflow-v4\/tooling\/longflow-g03-v4-(?:darwin|linux)-arm64-[a-f0-9]{12}$/.test(
      extractor.versioned_path
    ),
    'fixed_longflow_binary_path_required'
  );
  options.ensembleBinaryRaw = readSafe(
    path.resolve(root, ensemble.versioned_path)
  );
  options.engineBinaryRaw = readSafe(
    path.resolve(root, tooling.score_engine.versioned_path)
  );
  options.longflowBinaryRaw = readSafe(
    path.resolve(root, extractor.versioned_path)
  );
  options.analysisContractRaw = readSafe(
    path.join(root, 'lab/dpi-g03/ANALYSIS-R4.md')
  );
  options.binaryKey = binaryKey;
  options.readAuthorized = args['--authorize-read'] === true;
  options.fitAuthorized = args['--authorize-fit'] === true;
  const result = build(options);
  mkdir(path.dirname(out), { recursive: true });
  mkdir(out, { mode: 0o700 });
  for (const [name, raw] of [
    ['data-release.json', result.releaseRaw],
    ['ensemble-b1.json', result.projectionRaw],
    ['index-union-descriptor.json', result.descriptorRaw]
  ])
    write(path.join(out, name), raw, { flag: 'wx', mode: 0o600 });
  return { directory: out, ...result.bindings };
}
if (require.main === module) {
  try {
    console.log(JSON.stringify(main(process.argv.slice(2))));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
module.exports = { preflight, build, main, argumentsFor, CONTRACT };

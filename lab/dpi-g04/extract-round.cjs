'use strict';
// Post-hoc development view, not a fit or a fresh acquisition. No data is read
// before a persisted declaration plus explicit --authorize-read.
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto'),
  cp = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { guardRound } = require('../dpi-g03/review-round.cjs');
const { argumentsFor, validateMeta } = require('./extract.cjs');
const ORIGINAL_HELPER_SHA =
  'b0268674f355627ead0aaaf74441b3fb577e3442d7be347c49c2e610b52b7c0c';
const ROOT = path.resolve(__dirname, '../..');
const C = '9be744e6aebb9bbd73a0b9b2c861f01f82f30978ec331d366dfa611232f23184';
const O = '3bedeecc9596777cf4f858748590a9c3b0380bc78b84de0518fd7a051972ca42';
const L = 'caab5bbb1020062eb14d59ebf1ed769050143e3a81417fbd8b8db7045553c649';
const OFFSETS = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78],
  MAX_PCAP = 268435456,
  TIMEOUT = 60000;
const hash = (raw) => crypto.createHash('sha256').update(raw).digest('hex');
const encode = (x) => Buffer.from(JSON.stringify(x, null, 2) + '\n');
const hex = (x) => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const need = (x, error) => {
  if (!x) throw Error(error);
};
function safe(file) {
  need(
    typeof file === 'string' &&
      file.length > 0 &&
      !/vault|sealed[-_]|(?:^|[\\/])b-test-|(?:^|[\\/])b2(?:[\\/]|$)|(?:^|[\\/])q-(?:r|20)/i.test(
        file
      ),
    'test_Q_vault_path_forbidden'
  );
  return file;
}
function initialPolicyRef(r){
  const declared=safe(r?.path);
  need(hex(r.sha256),'initial_DPI_policy_reference_required');
  if(!path.isAbsolute(declared))need(!declared.split(/[\\/]/).includes('..'),'initial_DPI_relative_path_traversal');
  return{path:path.resolve(ROOT,declared),sha256:r.sha256,source_declared_path:declared};
}
function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}
function sourcePins(tool, root, name) {
  need(
    tool.source_sha256 && Object.keys(tool.source_sha256).length > 0,
    'complete_source_manifest_required'
  );
  const list = [];
  for (const [file, sha] of Object.entries(tool.source_sha256)) {
    need(
      new RegExp(
        '^lab/dpi-g04/' + name + '/[a-zA-Z0-9_.-]+\\.(?:go|cjs|json|md)$'
      ).test(file) && hex(sha),
      'fixed_source_paths_required'
    );
    list.push({ path: path.resolve(root, file), sha256: sha });
  }
  for (const [file, sha] of Object.entries(tool.module_sha256 || {})) {
    need(
      ['go.mod', 'go.sum'].includes(file) && hex(sha),
      'fixed_module_pins_required'
    );
    list.push({ path: path.resolve(root, file), sha256: sha });
  }
  return list;
}
function tooling(raw, root, name, now) {
  const t = JSON.parse(raw),
    schema = name === 'observer' ? 6 : 4;
  need(
    t.schema === schema &&
      t.version === `g04-header-${name}-v1` &&
      t.evidence_unit === 'tls23_header_declared_length' &&
      t.coverage_semantics_sha256 === C &&
      t.ordering_semantics_sha256 === O &&
      (name !== 'longflow' || t.feature_definitions_sha256 === L),
    'exact_header_tooling_contract_required'
  );
  need(
    Number.isFinite(Date.parse(t.created_at)) &&
      Date.parse(t.created_at) <= Date.parse(now),
    'tooling_from_future'
  );
  const b = t.binary?.[name];
  need(
    hex(b?.sha256) &&
      typeof b.versioned_path === 'string' &&
      new RegExp(
        '^lab/dpi-g04/' +
          name +
          '/tooling/' +
          name +
          '-g04-header-v1-darwin-arm64-[a-f0-9]{12}$'
      ).test(b.versioned_path),
    'selected_Darwin_versioned_binary_required'
  );
  return {
    descriptor: t,
    binary: { path: path.resolve(root, b.versioned_path), sha256: b.sha256 },
    sources: sourcePins(t, root, name)
  };
}
// Round-specific metadata gate. The original71 gate/driver stays immutable.
function preflight(options) {
  const master = JSON.parse(options.masterRaw),
    audit = JSON.parse(options.auditRaw),
    collectorSHA = hash(options.masterRaw);
  guardRound(master);
  need(
    path.isAbsolute(safe(options.masterPath)),
    'absolute_round_master_required'
  );
  const n = master.groups.length;
  need(
    master.prefix_grace_seconds === 2 &&
      master.pcap_cap_bytes === MAX_PCAP &&
      same(master.window_offsets_seconds, OFFSETS) &&
      Object.values(master.files_sha256).every(hex),
    'same80s_header_view_contract_required'
  );
  need(
    master.groups.every(
      (g) =>
        g.transport === 'reality' &&
        typeof g.profile === 'string' &&
        g.profile.length > 0 &&
        typeof g.source_workload_id === 'string' &&
        g.source_workload_id.length > 0 &&
        typeof g.client_stack === 'string' &&
        g.client_stack.length > 0
    ),
    'complete_native_metadata_required'
  );
  const sources = new Map();
  for (const g of master.groups) {
    need(
      !sources.has(g.source_workload_id) ||
        sources.get(g.source_workload_id) === g.split,
      'source_workload_split_leakage'
    );
    sources.set(g.source_workload_id, g.split);
  }
  need(
    audit.schema === 'g03-root-adaptive-round-acquisition/v1' &&
      audit.stage === 'B1' &&
      audit.adaptive_round === master.adaptive_round &&
      audit.experiment_role === 'candidate-development' &&
      audit.terminal_completed === true &&
      audit.restoration_complete === true &&
      audit.expected_groups === n &&
      audit.reviewed_groups === n &&
      audit.missing_groups?.length === 0 &&
      audit.errors?.length === 0,
    'terminal_restored_exact_round_audit_required'
  );
  need(
    audit.private_test_values_read === false &&
      audit.detector_fitting_performed === false &&
      audit.auditor_sha256 === options.auditorSHA,
    'independent_round_auditor_binding_required'
  );
  need(
    audit.frozen_collector_sha256 === collectorSHA &&
      audit.collector_freeze?.path === options.masterPath &&
      audit.collector_freeze.sha256 === collectorSHA,
    'audit_exact_round_master_required'
  );
  need(
    audit.groups?.length === n &&
      new Set(audit.groups.map((g) => g.group_id)).size === n &&
      audit.groups.every(
        (g) =>
          master.groups.some((a) => a.group_id === g.group_id) &&
          Array.isArray(g.errors)
      ),
    'exact_round_group_inventory_required'
  );
  const semanticOnly =
    audit.semantic_only_unknown_allowed === true &&
    audit.raw_acquisition_qualified === true &&
    audit.analysis_input_allowed === true;
  if (semanticOnly)
    need(
      audit.nonsemantic_failures?.length === 0 &&
        audit.groups.every((g) =>
          g.errors.every((e) => e === 'reporter_coverage_unknown')
        ),
      'raw_failures_cannot_be_waived'
    );
  else
    need(
      audit.acquisition_qualified === true &&
        audit.groups.every(
          (g) => g.acquisition_qualified === true && g.errors.length === 0
        ),
      'strict_raw_round_acquisition_required'
    );
  need(
    audit.pins?.length === Object.keys(master.files_sha256).length &&
      new Set(audit.pins.map((p) => p.path)).size === audit.pins.length &&
      audit.pins.every(
        (p) => Object.hasOwn(master.files_sha256, p.path) && p.matches === true
      ),
    'all_round_source_pins_must_match'
  );
  need(
    master.prepared &&
      audit.prepared?.path === path.resolve(master.prepared.path) &&
      audit.prepared.sha256 === master.prepared.sha256 &&
      audit.prepared.assets_checked > 0 &&
      audit.prepared.binaries_checked >= 2 &&
      hex(audit.candidate_elf_sha256),
    'round_candidate_preparation_binding_required'
  );
  const index = audit.observer_index;
  need(
    index &&
      path.isAbsolute(safe(index.path)) &&
      hex(index.sha256) &&
      audit.input_sha256?.[index.path] === index.sha256 &&
      audit.input_sha256?.[options.masterPath] === collectorSHA &&
      audit.input_sha256?.[audit.prepared.path] === master.prepared.sha256,
    'audited_round_index_and_input_hashes_required'
  );
  const times = [
    master.frozen_at,
    audit.completion_finished_utc,
    audit.checked_utc,
    options.now
  ].map(Date.parse);
  need(
    times.every(Number.isFinite) &&
      times[1] > times[0] &&
      times[2] >= times[1] &&
      times[3] >= times[2],
    'declaration_must_follow_round_completion'
  );
  return {
    master,
    audit,
    collectorSHA,
    groups: master.groups.map((g) => ({
      ...Object.fromEntries(
        [
          'group_id',
          'source_workload_id',
          'scope',
          'transport',
          'client_stack',
          'split',
          'class',
          'profile',
          'family',
          'adaptive_round',
          'experiment_role'
        ].map((k) => [k, g[k]])
      ),
      collector_freeze_sha256: collectorSHA
    })),
    unknown: audit.groups
      .filter((g) => g.errors.includes('reporter_coverage_unknown'))
      .map((g) => g.group_id)
  };
}

// Pure metadata references only: this never opens an index/report/PCAP.
function makePlan(options) {
  const p = preflight(options),
    root = options.root || ROOT,
    a = p.audit;
  need(
    hex(p.master.test_seeds_commitment?.sha256) &&
      [0, 25].includes(p.master.test_seeds_commitment.test_groups),
    'original_test_commitment_required_no_values_read'
  );
  const ob = tooling(options.observerToolingRaw, root, 'observer', options.now),
    lf = tooling(options.longflowToolingRaw, root, 'longflow', options.now),
    dir = path.dirname(a.observer_index.path);
  const ref = (file) => {
    file = path.resolve(safe(file));
    need(
      hex(a.input_sha256[file]),
      'independent_raw_input_hash_required:' + file
    );
    return { path: file, sha256: a.input_sha256[file] };
  };
  const groups = p.groups.map((g) => {
    const base = path.join(dir, g.group_id),
      pcap = ref(path.join(base, 'outer.pcap')),
      windows = ref(path.join(base, 'windows.json')),
      meta = path.join(base, 'observer-meta.json');
    return {
      ...g,
      pcap,
      original_windows: windows,
      metadata_source: Object.hasOwn(a.input_sha256, meta)
        ? { kind: 'pinned_observer_metadata', ...ref(meta) }
        : { kind: 'pinned_original_windows_metadata_only', ...windows }
    };
  });
  const filePins = [...ob.sources, ...lf.sources, ob.binary, lf.binary];
  const unique = new Map();
  for (const r of filePins) {
    if (unique.has(r.path))
      need(unique.get(r.path).sha256 === r.sha256, 'conflicting_tool_pins');
    unique.set(r.path, r);
  }
  return {
    master: p.master,
    audit: a,
    groups,
    binaries: { observer: ob.binary, longflow: lf.binary },
    sourcePins: [...unique.values()],
    declaration: {
      schema: 'g04-header-extraction-declaration/v1',
      declared_at: options.now,
      stage: 'B1',
      role: 'posthoc_adaptive_round_header_view',
      adaptive_round: p.master.adaptive_round,
      experiment_role: 'candidate-development',
      candidate_elf_sha256: a.candidate_elf_sha256,
      original_semantic_unknown_groups: p.unknown,
      posthoc_development: true,
      not_a_fresh_acquisition: true,
      not_an_adaptive_transport_cycle: true,
      read_authorized: options.readAuthorized === true,
      classifier_fitting_authorized: false,
      private_test_values_read: false,
      original_test_commitment_sha256: p.master.test_seeds_commitment.sha256,
      analysis_contract: 'r4-worst-case-benign-fp-v1',
      collector_freeze: { path: options.masterPath, sha256: p.collectorSHA },
      independent_analysis_release: {
        path: options.auditPath,
        sha256: hash(options.auditRaw)
      },
      original_observer_index: a.observer_index,
      observer_tooling: {
        path: options.observerToolingPath,
        sha256: hash(options.observerToolingRaw),
        schema: 6,
        version: ob.descriptor.version,
        binary: ob.binary
      },
      longflow_tooling: {
        path: options.longflowToolingPath,
        sha256: hash(options.longflowToolingRaw),
        schema: 4,
        version: lf.descriptor.version,
        binary: lf.binary
      },
      coverage_semantics_sha256: C,
      ordering_semantics_sha256: O,
      longflow_definitions_sha256: L,
      evidence_unit: 'tls23_header_declared_length',
      measured_seconds: 80,
      capture_seconds: 82,
      prefix_grace_seconds: 2,
      window_offsets_seconds: OFFSETS,
      capture_cap_bytes: MAX_PCAP,
      per_group_process_deadline_ms: TIMEOUT,
      max_concurrent_processes: 1,
      invocation_policy:
        'each selected binary at most once per group; no retries; exhausted group deadline is explicit failure',
      extractor_selection_follows_completed_development: true,
      fresh_test_must_follow_this_declaration: true,
      toolchain_pins: [...unique.values()],
      groups
    }
  };
}
function validateIndex(index, plan) {
  need(
    index.schema === 4 &&
      index.stage === 'B1' &&
      index.reports?.length === plan.groups.length &&
      new Set(index.reports.map((r) => r.group_id)).size === plan.groups.length,
    'exact_original_typed_round_index_required'
  );
  need(
    index.coverage_errors === undefined ||
      (Array.isArray(index.coverage_errors) &&
        index.coverage_errors.every((x) => typeof x === 'string')),
    'raw_index_coverage_type'
  );
  for (const r of index.reports) {
    const g = plan.groups.find((g) => g.group_id === r.group_id);
    need(
      g &&
        r.split === g.split &&
        r.path === g.group_id + '/windows.json' &&
        r.longflow_path === g.group_id + '/longflow.json' &&
        Array.isArray(r.coverage_errors) &&
        r.coverage_errors.every((x) => typeof x === 'string'),
      'original_index_assignment_or_raw_coverage_mismatch'
    );
  }
}
function streamingHash(file, maxBytes) {
  const fd = fs.openSync(file, 'r'),
    h = crypto.createHash('sha256'),
    buffer = Buffer.alloc(64 * 1024);
  let bytes = 0;
  try {
    while (true) {
      const n = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!n) break;
      bytes += n;
      need(bytes <= maxBytes, 'input_exceeds_declared_cap');
      h.update(buffer.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
  return h.digest('hex');
}
function main(argv, io = {}) {
  const a = argumentsFor(argv),
    root = io.root || ROOT,
    read = io.readFileSync || fs.readFileSync,
    write = io.writeFileSync || fs.writeFileSync,
    mkdir = io.mkdirSync || fs.mkdirSync,
    exists = io.existsSync || fs.existsSync,
    spawn = io.spawnSync || cp.spawnSync,
    mono = io.monotonicMS || (() => performance.now()),
    utc = io.utc || (() => new Date().toISOString()),
    hashFile = io.hashFileSync || streamingHash;
  const out = path.resolve(safe(a['--out-dir']));
  need(!exists(out), 'NEW_output_required_no_overwrite');
  const metadataRead = (file) => Buffer.from(read(safe(file)));
  const masterPath = path.resolve(safe(a['--master'])),
    auditPath = path.resolve(safe(a['--audit'])),
    observerToolingPath = path.resolve(safe(a['--observer-tooling'])),
    longflowToolingPath = path.resolve(safe(a['--longflow-tooling']));
  const masterRaw = metadataRead(masterPath),
    auditRaw = metadataRead(auditPath),
    auditorPath = path.join(root, 'lab/dpi-g03/review-round.cjs'),
    auditorRaw = metadataRead(auditorPath),
    now = utc();
  const basic = {
    masterRaw,
    auditRaw,
    masterPath,
    auditorSHA: hash(auditorRaw),
    now
  };
  preflight(basic); // BEFORE tool or group references.
  const plan = makePlan({
    ...basic,
    root,
    auditPath,
    observerToolingPath,
    longflowToolingPath,
    observerToolingRaw: metadataRead(observerToolingPath),
    longflowToolingRaw: metadataRead(longflowToolingPath),
    readAuthorized: a['--authorize-read'] === true
  });
  const dependencyPath = path.join(root, 'lab/dpi-g04/extract.cjs'),
    driverPath = path.join(root, 'lab/dpi-g04/extract-round.cjs');
  const frozenHelperRaw = metadataRead(dependencyPath);
  need(
    hash(frozenHelperRaw) === ORIGINAL_HELPER_SHA,
    'original71_helper_changed'
  );
  if (plan.master.assignments) {
    const r = plan.master.assignments;
    need(
      path.isAbsolute(safe(r.path)) && hex(r.sha256),
      'frozen_candidate_plan_reference_required'
    );
    const raw = metadataRead(r.path);
    need(hash(raw) === r.sha256, 'frozen_candidate_plan_changed');
    const candidate = JSON.parse(raw);
    need(
      candidate.cycle === plan.master.adaptive_round &&
        candidate.experiment_role === 'candidate-development' &&
        candidate.test_rows === 0,
      'candidate_plan_round_mismatch'
    );
    plan.declaration.frozen_candidate_plan = { path: r.path, sha256: r.sha256 };
    need(
      candidate.groups?.length === plan.groups.length &&
        candidate.groups.every(
          (g, i) => g.group_id === plan.groups[i].group_id
        ),
      'candidate_plan_inventory_mismatch'
    );
    if (candidate.initial_dpi_policy) {
      plan.declaration.initial_dpi_policy = initialPolicyRef(candidate.initial_dpi_policy);
    }
  }
  const extra = [
    { path: masterPath, sha256: hash(masterRaw) },
    { path: auditPath, sha256: hash(auditRaw) },
    { path: auditorPath, sha256: hash(auditorRaw) },
    { path: dependencyPath, sha256: hash(metadataRead(dependencyPath)) },
    { path: driverPath, sha256: hash(metadataRead(driverPath)) },
    {
      path: observerToolingPath,
      sha256: hash(metadataRead(observerToolingPath))
    },
    {
      path: longflowToolingPath,
      sha256: hash(metadataRead(longflowToolingPath))
    }
  ];
  const pins = [
    ...plan.sourcePins,
    ...extra,
    ...(plan.declaration.frozen_candidate_plan
      ? [plan.declaration.frozen_candidate_plan]
      : [])
  ];
  const verifyTools = () => {
    for (const r of pins)
      need(
        hash(metadataRead(r.path)) === r.sha256,
        'toolchain_or_metadata_changed:' + r.path
      );
  };
  verifyTools();
  plan.declaration.toolchain_pins = pins;
  plan.declaration.source_and_binary_integrity_verified = true;
  mkdir(path.dirname(out), { recursive: true });
  mkdir(out, { mode: 0o700 });
  const declPath = path.join(out, 'DECLARATION.json'),
    declRaw = encode(plan.declaration),
    declSHA = hash(declRaw);
  write(declPath, declRaw, { flag: 'wx', mode: 0o600 });
  const guarded = () => {
    need(
      a['--authorize-read'] === true,
      'explicit_read_authorization_required'
    );
    need(
      hash(metadataRead(declPath)) === declSHA,
      'persisted_declaration_changed'
    );
  };
  const checkedRaw = (r) => {
    guarded();
    const raw = metadataRead(r.path);
    need(hash(raw) === r.sha256, 'audited_raw_input_changed:' + r.path);
    return raw;
  };
  const checkedPCAP = (r) => {
    guarded();
    need(
      hashFile(r.path, MAX_PCAP) === r.sha256,
      'audited_PCAP_changed:' + r.path
    );
  };
  if (a['--authorize-read'] !== true)
    return {
      directory: out,
      declaration_sha256: declSHA,
      status: 'declaration_only',
      actual_group_or_index_or_PCAP_reads: 0,
      classifier_fitting_performed: false
    };
  const manifest = {
    schema: 'g04-header-extraction/v1',
    adaptive_round: plan.master.adaptive_round,
    experiment_role: 'candidate-development',
    input_master_sha256: plan.declaration.collector_freeze.sha256,
    root_release_sha256: hash(auditRaw),
    declaration: { path: declPath, sha256: declSHA },
    observer_index: null,
    complete: false,
    integrity_errors: [],
    declaration_sha256: declSHA,
    started_at: utc(),
    finished: false,
    global_integrity: true,
    classifier_fitting_performed: false,
    private_test_values_read: false,
    groups: [],
    errors: [],
    toolchain_before_sha256: Object.fromEntries(
      pins.map((p) => [p.path, p.sha256])
    ),
    toolchain_after_sha256: null
  };
  const saveManifest = () => {
    manifest.integrity_errors = [
      ...manifest.errors,
      ...manifest.groups.flatMap((g) =>
        g.errors.map((error) => g.group_id + ':' + error)
      )
    ];
    manifest.complete =
      manifest.finished &&
      manifest.global_integrity &&
      manifest.groups.length === plan.groups.length &&
      manifest.groups.every((g) => g.finished);
    write(path.join(out, 'EXTRACTION.json'), encode(manifest), { mode: 0o600 });
  };
  saveManifest();
  const result = {
    directory: out,
    declaration_sha256: declSHA,
    status: 'extraction',
    global_integrity: false,
    groups: 0,
    classifier_fitting_performed: false
  };
  try {
    const original = JSON.parse(checkedRaw(plan.audit.observer_index));
    validateIndex(original, plan);
    const index = {
      schema: 4,
      stage: 'B1',
      coverage_errors: [...(original.coverage_errors || [])],
      reports: plan.groups.map((g) => {
        const r = original.reports.find((r) => r.group_id === g.group_id);
        return {
          group_id: g.group_id,
          split: g.split,
          path: g.group_id + '/windows.json',
          longflow_path: g.group_id + '/longflow.json',
          coverage_errors: [...r.coverage_errors]
        };
      })
    };
    const indexPath = path.join(out, 'observer-index.json');
    write(indexPath, encode(index), { flag: 'wx', mode: 0o600 });
    manifest.observer_index = { path: indexPath, sha256: hash(encode(index)) };
    if (
      index.coverage_errors.length ||
      index.reports.some((r) => r.coverage_errors.length)
    ) {
      manifest.global_integrity = false;
      manifest.errors.push('original_raw_index_has_coverage_errors');
    }
    for (const g of plan.groups) {
      guarded();
      const dir = path.join(out, g.group_id);
      mkdir(dir, { mode: 0o700 });
      const state = {
        group_id: g.group_id,
        split: g.split,
        pcap: g.pcap,
        metadata_source: g.metadata_source,
        raw_input_before_verified: false,
        raw_input_after_verified: false,
        attempts: [],
        outputs: {},
        errors: [],
        finished: false
      };
      manifest.groups.push(state);
      saveManifest();
      try {
        checkedPCAP(g.pcap);
        let metaRaw = checkedRaw(g.metadata_source),
          meta;
        if (g.metadata_source.kind === 'pinned_observer_metadata')
          meta = JSON.parse(metaRaw);
        else {
          meta = JSON.parse(metaRaw).metadata;
          metaRaw = encode(meta);
        }
        validateMeta(meta, g, plan.declaration.collector_freeze.sha256);
        state.raw_input_before_verified = true;
        const metaPath = path.join(dir, 'observer-meta.json');
        write(metaPath, metaRaw, { flag: 'wx', mode: 0o600 });
        state.derived_metadata_sha256 = hash(metaRaw);
        const groupDeadline = mono() + TIMEOUT;
        for (const name of ['observer', 'longflow']) {
          guarded();
          const program = plan.binaries[name],
            file = path.join(
              dir,
              name === 'observer' ? 'windows.json' : 'longflow.json'
            ),
            remaining = Math.floor(groupDeadline - mono());
          const attempt = {
            name,
            program,
            started_at: utc(),
            timeout_ms: Math.max(0, remaining),
            invoked: false
          };
          state.attempts.push(attempt);
          saveManifest();
          if (remaining <= 0) {
            attempt.error = 'group_deadline_exhausted_not_started';
            state.errors.push(name + ':group_deadline_exhausted_not_started');
            continue;
          }
          need(
            hash(metadataRead(program.path)) === program.sha256,
            'binary_changed_before_exec'
          );
          need(
            hash(metadataRead(metaPath)) === state.derived_metadata_sha256,
            'derived_metadata_changed'
          );
          attempt.invoked = true;
          const processStarted = mono();
          saveManifest();
          let child;
          try {
            child = spawn(
              program.path,
              ['-pcap', g.pcap.path, '-meta', metaPath, '-out', file],
              {
                cwd: root,
                shell: false,
                timeout: remaining,
                killSignal: 'SIGKILL',
                maxBuffer: 2 * 1024 * 1024,
                encoding: null
              }
            );
          } catch (error) {
            child = {
              status: null,
              error,
              stdout: Buffer.alloc(0),
              stderr: Buffer.alloc(0)
            };
          }
          attempt.finished_at = utc();
          attempt.elapsed_ms = mono() - processStarted;
          if (mono() > groupDeadline)
            state.errors.push(name + ':group_deadline_exceeded');
          attempt.status = child.status ?? null;
          attempt.signal = child.signal ?? null;
          attempt.error = child.error?.code || child.error?.message || null;
          for (const key of ['stdout', 'stderr']) {
            const p = path.join(dir, name + '.' + key + '.log'),
              raw = Buffer.from(child[key] || '');
            write(p, raw, { flag: 'wx', mode: 0o600 });
            attempt[key] = { path: path.basename(p), sha256: hash(raw) };
          }
          attempt.binary_after_sha256 = hash(metadataRead(program.path));
          need(
            attempt.binary_after_sha256 === program.sha256,
            'binary_changed_during_exec'
          );
          if (exists(file)) {
            const raw = metadataRead(file);
            state.outputs[name] = {
              path: path.basename(file),
              sha256: hash(raw)
            };
            try {
              const report = JSON.parse(raw);
              need(
                report.schema === (name === 'observer' ? 6 : 4) &&
                  report.version === `g04-header-${name}-v1` &&
                  report.evidence_unit === 'tls23_header_declared_length' &&
                  report.coverage_semantics_sha256 === C &&
                  report.ordering_semantics_sha256 === O &&
                  report.pcap_sha256 === g.pcap.sha256,
                'new_output_view_or_PCAP_binding'
              );
              validateMeta(
                report.metadata,
                g,
                plan.declaration.collector_freeze.sha256
              );
              need(
                name !== 'longflow' || report.feature_definitions_sha256 === L,
                'new_longflow_definition_binding'
              );
              const coverage =
                name === 'observer'
                  ? report.coverage_complete
                  : report.source_observer_coverage_complete;
              need(
                typeof coverage === 'boolean',
                'explicit_view_coverage_required'
              );
              state.outputs[name].coverage_complete = coverage;
            } catch (error) {
              state.errors.push(name + ':' + error.message);
            }
          } else state.errors.push(name + ':output_missing');
          if (child.status !== 0 || child.error || child.signal)
            state.errors.push(name + ':process_failed');
          saveManifest();
        }
        checkedPCAP(g.pcap);
        checkedRaw(g.metadata_source);
        state.raw_input_after_verified = true;
        for (const output of Object.values(state.outputs))
          need(
            hash(metadataRead(path.join(dir, output.path))) === output.sha256,
            'generated_output_changed'
          );
        need(
          hash(metadataRead(metaPath)) === state.derived_metadata_sha256,
          'derived_metadata_changed_after_exec'
        );
      } catch (error) {
        state.errors.push(error.message);
      }
      state.finished = true;
      state.finished_at = utc();
      if (state.errors.length) manifest.global_integrity = false;
      saveManifest();
    }
    manifest.toolchain_after_sha256 = {};
    for (const p of pins) {
      try {
        manifest.toolchain_after_sha256[p.path] = hash(metadataRead(p.path));
      } catch (error) {
        manifest.toolchain_after_sha256[p.path] = null;
        manifest.errors.push('toolchain_after_unreadable:' + p.path);
      }
    }
    verifyTools();
    manifest.index_sha256 = hash(metadataRead(indexPath));
    need(
      manifest.index_sha256 === manifest.observer_index.sha256,
      'generated_index_changed'
    );
    manifest.semantic_unknown_groups = manifest.groups
      .filter((g) =>
        Object.values(g.outputs).some((o) => o.coverage_complete === false)
      )
      .map((g) => g.group_id);
    manifest.finished = true;
    manifest.finished_at = utc();
    result.groups = manifest.groups.length;
    result.global_integrity = manifest.global_integrity;
  } catch (error) {
    manifest.global_integrity = false;
    manifest.errors.push(error.message);
    manifest.finished_at = utc();
    result.error = error.message;
  }
  result.groups = manifest.groups.length;
  saveManifest();
  return result;
}
if (require.main === module) {
  try {
    const r = main(process.argv.slice(2));
    console.log(JSON.stringify(r));
    if (r.status === 'extraction' && !r.global_integrity) process.exitCode = 2;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
module.exports = {
  initialPolicyRef,
  preflight,
  makePlan,
  main,
  argumentsFor,
  validateIndex,
  validateMeta
};

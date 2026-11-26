'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  preflight,
  build,
  main,
  argumentsFor,
  CONTRACT
} = require('./project.cjs');
const H = (n) => n.toString(16).padStart(64, '0');
const hash = (b) => crypto.createHash('sha256').update(b).digest('hex');
const encode = (x) => Buffer.from(JSON.stringify(x));
const C = '5591ec10229a2cc49325fe709ce19a4fcad882858f4f2490f4fda343ed987810';
const O = 'a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1';
const L = '9d866dd631df3601630ee0f3ce0c00383f50a46194bca44cd88349bffade864e';
const W = 'fe5a3d12c958b1d410aa4af5e75fa1fa24fbcc86bc41091ca62e50be6458bd87';
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g03-project-fixture-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const masterPath = path.join(root, 'master-b1.json'),
    auditPath = path.join(root, 'analysis-audit.json'),
    indexPath = path.join(root, 'raw', 'observer-index.json'),
    strictPath = path.join(root, 'strict-audit.json'),
    preparedPath = path.join(root, 'prepared.json'),
    toolingPath = path.join(root, 'tooling.json'),
    out = path.join(root, 'new-output');
  const auditor = Buffer.from('synthetic independent auditor source'),
    doc = Buffer.from('synthetic analysis contract');
  const engine = Buffer.from('synthetic score engine source fixture'),
    ensemble = Buffer.from('synthetic ensemble'),
    extractor = Buffer.from('synthetic LF');
  const enginePath =
    'out/dpi-g03/tooling-defender/classical-existing15-darwin-arm64-c5adef946409';
  const ensemblePath =
    'lab/dpi-g03/ensemble-v4/tooling/ensemble-g03-v4-darwin-arm64-123456789abc';
  const lfPath =
    'lab/dpi-g03/longflow-v4/tooling/longflow-g03-v4-darwin-arm64-123456789abc';
  const observerPath =
    'lab/dpi-g03/observer-v4/tooling/observer-g03-v4-darwin-arm64-123456789abc';
  const observer = {
    schema: 5,
    version: 'g03-observer-v4',
    created_at: '2026-01-01T00:00:00Z',
    coverage_semantics_sha256: C,
    ordering_semantics_sha256: O,
    binary: { observer: { sha256: H(10), versioned_path: observerPath } }
  };
  const longflow = {
    schema: 3,
    version: 'g03-longflow-v4',
    created_at: '2026-01-01T00:00:00Z',
    coverage_semantics_sha256: C,
    ordering_semantics_sha256: O,
    feature_definitions_sha256: L,
    binary: { longflow: { sha256: hash(extractor), versioned_path: lfPath } }
  };
  const tooling = {
    schema: 4,
    version: 'g03-ensemble-v4',
    analysis_contract: CONTRACT,
    analysis_contract_document: {
      path: 'lab/dpi-g03/ANALYSIS-R4.md',
      sha256: hash(doc)
    },
    created_at: '2026-01-01T02:00:00Z',
    definitions_sha256: H(20),
    window_definitions_sha256: W,
    longflow_definitions_sha256: L,
    coverage_semantics_sha256: C,
    ordering_semantics_sha256: O,
    score_engine: { sha256: hash(engine), versioned_path: enginePath },
    binary: {
      ensemble: { sha256: hash(ensemble), versioned_path: ensemblePath }
    },
    observer_descriptor_sha256: hash(encode(observer)),
    longflow_descriptor_sha256: hash(encode(longflow))
  };
  const groups = Array.from({ length: 71 }, (_, i) => ({
    group_id: 'b-' + i,
    source_workload_id: 's-' + i,
    scope: 'primary',
    transport: i < 12 ? 'reality' : 'ordinary-tls',
    client_stack: i < 12 ? 'belnet+sing-box' : 'chrome',
    split: i < 40 ? 'train' : 'validation',
    class: i < 12 ? 'belnet' : 'benign',
    profile: 'fixture-profile'
  }));
  const master = {
    schema: 'belnet-g03-collector/v4',
    stage: 'B1',
    frozen_at: '2026-01-01T01:00:00Z',
    groups,
    prepared: { path: preparedPath, sha256: H(30) },
    measured_seconds: 80,
    capture_seconds: 82,
    prefix_grace_seconds: 2,
    window_offsets_seconds: [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78],
    pcap_cap_bytes: 268435456,
    files_sha256: {
      'lab/dpi-g03/observer-v4/tooling/TOOLING.json': hash(encode(observer)),
      'lab/dpi-g03/longflow-v4/tooling/TOOLING.json': hash(encode(longflow)),
      [observerPath]: H(10),
      [lfPath]: hash(extractor),
      [enginePath]: hash(engine)
    },
    test_seeds_commitment: {
      path: path.join(root, 'sealed-test-vault.json'),
      sha256: H(999)
    }
  };
  const audit = {
    schema: 'g03-root-conservative-analysis-release/v1',
    analysis_contract: CONTRACT,
    stage: 'B1',
    analysis_input_allowed: true,
    raw_acquisition_complete: true,
    terminal_completed: true,
    expected_groups: 71,
    observed_groups: 71,
    semantic_coverage_complete: false,
    completion_finished_utc: '2026-01-01T02:00:01Z',
    checked_utc: '2026-01-01T02:00:02Z',
    private_test_values_read: false,
    classifier_fitting_performed: false,
    certified_policy_issued: false,
    auditor_sha256: hash(auditor),
    collector_freeze: { path: masterPath, sha256: hash(encode(master)) },
    frozen_collector_sha256: hash(encode(master)),
    observer_index: { path: indexPath, sha256: H(40) },
    strict_audit: { path: strictPath, sha256: H(41), auditor_sha256: H(42) },
    prepared: {
      path: preparedPath,
      sha256: H(30),
      assets_checked: 3,
      binaries_checked: 2
    },
    groups: groups.map((g, i) => ({
      group_id: g.group_id,
      raw_acquisition_qualified: true,
      strict_acquisition_qualified: i !== 18,
      semantic_unknown: i === 18,
      semantic_coverage_complete: i !== 18,
      primary_flow_inventory: ['f0', 'f1'],
      original_coverage_reasons:
        i === 18 ? ['primary_flow_fault: partial_TLS'] : []
    })),
    semantic_unknown_groups: ['b-18'],
    input_sha256: {
      [masterPath]: hash(encode(master)),
      [indexPath]: H(40),
      [strictPath]: H(41),
      [preparedPath]: H(30)
    }
  };
  const o = {
    masterPath,
    masterRaw: encode(master),
    auditRaw: encode(audit),
    toolingRaw: encode(tooling),
    observerRaw: encode(observer),
    longflowRaw: encode(longflow),
    ensembleBinaryRaw: ensemble,
    engineBinaryRaw: engine,
    longflowBinaryRaw: extractor,
    auditorSHA: hash(auditor),
    analysisContractRaw: doc,
    now: '2026-01-01T02:00:03Z',
    syntheticFixture: true,
    fixtureEngineSHA: hash(engine)
  };
  const reads = [];
  const map = new Map();
  const sync = () => {
    o.masterRaw = encode(master);
    audit.collector_freeze.sha256 = hash(o.masterRaw);
    audit.frozen_collector_sha256 = hash(o.masterRaw);
    audit.input_sha256[masterPath] = hash(o.masterRaw);
    o.auditRaw = encode(audit);
    o.toolingRaw = encode(tooling);
    o.observerRaw = encode(observer);
    o.longflowRaw = encode(longflow);
    map.set(masterPath, o.masterRaw);
    map.set(auditPath, o.auditRaw);
    map.set(toolingPath, o.toolingRaw);
    map.set(path.join(root, 'lab/dpi-g03/review-analysis-r4.cjs'), auditor);
    map.set(
      path.join(root, 'lab/dpi-g03/observer-v4/tooling/TOOLING.json'),
      o.observerRaw
    );
    map.set(
      path.join(root, 'lab/dpi-g03/longflow-v4/tooling/TOOLING.json'),
      o.longflowRaw
    );
    map.set(path.join(root, 'lab/dpi-g03/ANALYSIS-R4.md'), doc);
    map.set(path.join(root, enginePath), engine);
    map.set(path.join(root, ensemblePath), ensemble);
    map.set(path.join(root, lfPath), extractor);
  };
  sync();
  const io = {
    root,
    now: o.now,
    syntheticFixture: true,
    fixtureEngineSHA: hash(engine),
    readFileSync(file) {
      file = path.resolve(file);
      reads.push(file);
      assert.ok(
        !/observer-index|windows\.json|outer\.pcap|sealed-test-vault/.test(
          file
        ),
        'forbidden raw data read'
      );
      assert.ok(map.has(file), 'unexpected file read:' + file);
      return map.get(file);
    }
  };
  const argv = [
    '--master',
    masterPath,
    '--audit',
    auditPath,
    '--tooling',
    toolingPath,
    '--out-dir',
    out
  ];
  return {
    root,
    master,
    audit,
    tooling,
    observer,
    longflow,
    o,
    io,
    argv,
    reads,
    sync,
    indexPath,
    toolingPath,
    out,
    build() {
      return build(o);
    }
  };
}
test('Completed71 metadata produces conservative projection without reading any reports/index', (t) => {
  const f = fixture(t),
    r = f.build();
  assert.equal(r.projection.schema, 4);
  assert.equal(r.projection.analysis_contract, CONTRACT);
  assert.equal(r.projection.frozen_at, f.o.now);
  assert.notEqual(r.projection.frozen_at, f.master.frozen_at);
  assert.deepEqual(r.projection.collectors, [
    { path: f.o.masterPath, sha256: hash(f.o.masterRaw) }
  ]);
  assert.equal(
    r.projection.groups.every(
      (g) => g.collector_freeze_sha256 === hash(f.o.masterRaw)
    ),
    true
  );
  assert.equal(r.release.read_authorized, false);
  assert.equal(r.release.fit_authorized, false);
  assert.deepEqual(r.release.semantic_unknown_groups, ['b-18']);
  assert.equal(r.release.certified_policy_issued, false);
  assert.equal(r.descriptor.materialized, false);
  assert.equal(r.descriptor.input_indexes[0].path, f.indexPath);
  assert.equal(r.bindings.actual_index_or_report_or_vault_files_read, false);
  assert.equal(r.projection.synthetic_fixture, true);
});
test('Main writesNEW files usingonly metadata/source/binary reads; index staysunopened', (t) => {
  const f = fixture(t),
    r = main(f.argv, f.io);
  assert.equal(r.read_authorized, false);
  assert.equal(fs.readdirSync(f.out).length, 3);
  assert.equal(
    fs.statSync(path.join(f.out, 'ensemble-b1.json')).mode & 0o777,
    0o600
  );
  assert.equal(f.reads.includes(f.indexPath), false);
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(f.out, 'data-release.json')))
      .fit_authorized,
    false
  );
  assert.throws(
    () => main(f.argv, f.io),
    /new_output_directory_required_no_overwrite/
  );
});
test('Incomplete71 or missingterminal rejected beforetooling/index/reportIO', (t) => {
  for (const mode of ['groups', 'terminal', 'raw']) {
    const f = fixture(t);
    if (mode === 'groups') f.master.groups.pop();
    else if (mode === 'terminal') f.audit.terminal_completed = false;
    else f.audit.raw_acquisition_complete = false;
    f.sync();
    assert.throws(() => main(f.argv, f.io));
    assert.equal(f.reads.includes(f.toolingPath), false);
    assert.ok(f.reads.length <= 3);
    assert.equal(fs.existsSync(f.out), false);
  }
});
test('Q/test/diagnostic/source-split leaks reject beforefurtherIO', (t) => {
  for (const mode of ['Q', 'test', 'diagnostic', 'source']) {
    const f = fixture(t);
    if (mode === 'Q') f.master.stage = 'Q';
    else if (mode === 'test') f.master.groups[0].split = 'test';
    else if (mode === 'diagnostic') f.master.groups[0].scope = 'diagnostic';
    else
      f.master.groups[40].source_workload_id =
        f.master.groups[0].source_workload_id;
    f.sync();
    assert.throws(() => main(f.argv, f.io));
    assert.equal(f.reads.includes(f.toolingPath), false);
  }
});
test('Master/source/auditor/indexbindings reject mismatch without openingindex', (t) => {
  for (const mode of ['master', 'auditor', 'index', 'prepared']) {
    const f = fixture(t);
    if (mode === 'master')
      f.audit.collector_freeze.path = path.join(f.root, 'other-master.json');
    else if (mode === 'auditor') f.audit.auditor_sha256 = H(77);
    else if (mode === 'index') f.audit.input_sha256[f.indexPath] = H(77);
    else f.audit.prepared.assets_checked = 0;
    f.sync();
    assert.throws(() => main(f.argv, f.io));
    assert.equal(f.reads.includes(f.toolingPath), false);
  }
});
test('Posthocclassifier isallowed; posthocobservation tools arenot', (t) => {
  const f = fixture(t);
  assert.ok(Date.parse(f.tooling.created_at) > Date.parse(f.master.frozen_at));
  assert.equal(f.build().projection.schema, 4);
  f.observer.created_at = '2026-01-01T01:00:01Z';
  f.sync();
  assert.throws(() => f.build(), /observation_tools_must_precede_capture/);
});
test('SemanticUNKNOWN retained but malformed/unbounded inventories cannotrelease', (t) => {
  for (const mode of ['raw', 'inventory', 'census']) {
    const f = fixture(t);
    if (mode === 'raw') f.audit.groups[18].raw_acquisition_qualified = false;
    else if (mode === 'inventory')
      f.audit.groups[18].primary_flow_inventory = ['f0', 'f0'];
    else f.audit.semantic_unknown_groups = [];
    f.sync();
    assert.throws(() => f.build());
  }
});
test('Projection andcollector timing cannot be silentlychanged', (t) => {
  for (const mode of ['80', 'offsets', 'auditfuture', 'completion']) {
    const f = fixture(t);
    if (mode === '80') f.master.measured_seconds = 45;
    else if (mode === 'offsets') f.master.window_offsets_seconds = [8, 16];
    else if (mode === 'auditfuture')
      f.audit.checked_utc = '2026-01-01T02:00:04Z';
    else f.audit.completion_finished_utc = '2026-01-01T00:00:00Z';
    f.sync();
    assert.throws(() => f.build());
  }
});
test('Finalv4 descriptors/document andbinarySHAare mandatory', (t) => {
  for (const mode of ['version', 'document', 'binary', 'prepin']) {
    const f = fixture(t);
    if (mode === 'version') f.tooling.version = 'g03-ensemble-v3';
    else if (mode === 'document')
      f.tooling.analysis_contract_document.sha256 = H(76);
    else if (mode === 'binary') f.o.ensembleBinaryRaw = Buffer.from('tampered');
    else
      f.master.files_sha256[
        Object.keys(f.master.files_sha256).find((k) =>
          k.includes('longflow-g03')
        )
      ] = H(76);
    f.sync();
    assert.throws(() => f.build());
  }
});
test('Fitrequiresread; syntheticfixtures cannotauthorize either', (t) => {
  const f = fixture(t);
  f.o.fitAuthorized = true;
  assert.throws(() => f.build(), /synthetic_fixtures_cannot_authorize_data/);
  f.o.readAuthorized = true;
  assert.throws(() => f.build(), /synthetic_fixtures_cannot_authorize_data/);
  assert.throws(
    () => argumentsFor(['--authorize-fit']),
    /explicit_master_audit_tooling_new_output_required/
  );
});
test('Vaultpath andmalicioustooling path aredenied beforefileIO', (t) => {
  const f = fixture(t);
  f.audit.observer_index.path = path.join(f.root, 'sealed-test-vault.json');
  f.sync();
  assert.throws(() => main(f.argv, f.io), /test_Q_vault_path_forbidden/);
  assert.equal(f.reads.includes(f.toolingPath), false);
  const g = fixture(t);
  g.tooling.binary.ensemble.versioned_path = g.indexPath;
  g.sync();
  assert.throws(
    () => main(g.argv, g.io),
    /fixed_tooling_binary_paths_required/
  );
  assert.equal(g.reads.includes(g.indexPath), false);
});

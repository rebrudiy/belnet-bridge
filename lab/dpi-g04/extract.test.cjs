'use strict';
const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs'),
  os = require('node:os'),
  path = require('node:path'),
  crypto = require('node:crypto');
const { main, makePlan } = require('./extract.cjs');
const hash = (b) => crypto.createHash('sha256').update(b).digest('hex'),
  encode = (x) => Buffer.from(JSON.stringify(x)),
  H = (n) => n.toString(16).padStart(64, '0');
const C = '9be744e6aebb9bbd73a0b9b2c861f01f82f30978ec331d366dfa611232f23184',
  O = '3bedeecc9596777cf4f858748590a9c3b0380bc78b84de0518fd7a051972ca42',
  L = 'caab5bbb1020062eb14d59ebf1ed769050143e3a81417fbd8b8db7045553c649';
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g04-driver-synthetic-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const map = new Map(),
    events = [],
    calls = [],
    out = path.join(root, 'new-view'),
    masterPath = path.join(root, 'master-b1.json'),
    auditPath = path.join(root, 'audit.json'),
    indexPath = path.join(root, 'old', 'observer-index.json'),
    preparedPath = path.join(root, 'prepared.json'),
    strictPath = path.join(root, 'strict.json');
  const auditor = Buffer.from('synthetic auditor'),
    pcap = Buffer.from('synthetic-PCAP-bytes-NOT-real-traffic'),
    deps = ['lab/dpi-g03/adaptive/project.cjs', 'lab/dpi-g04/extract.cjs'];
  for (const p of deps)
    map.set(path.join(root, p), Buffer.from('synthetic code ' + p));
  map.set(path.join(root, 'lab/dpi-g03/review-analysis-r4.cjs'), auditor);
  const groups = Array.from({ length: 71 }, (_, i) => ({
    group_id: 'b-synthetic-' + i,
    source_workload_id: 's-' + i,
    scope: 'primary',
    transport: i < 12 ? 'reality' : 'ordinary-tls',
    client_stack: i < 12 ? 'native' : 'chrome',
    split: i < 40 ? 'train' : 'validation',
    class: i < 12 ? 'belnet' : 'benign',
    profile: 'fixture'
  }));
  const master = {
    schema: 'belnet-g03-collector/v4',
    stage: 'B1',
    frozen_at: '2026-01-01T01:00:00Z',
    groups,
    prepared: { path: preparedPath, sha256: H(3) },
    test_seeds_commitment: {
      path: path.join(root, 'sealed-test-vault.json'),
      sha256: H(900),
      test_groups: 25
    },
    files_sha256: { 'source.cjs': H(4) },
    measured_seconds: 80,
    capture_seconds: 82,
    prefix_grace_seconds: 2,
    pcap_cap_bytes: 268435456,
    window_offsets_seconds: [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78]
  };
  const oldIndex = {
    schema: 4,
    stage: 'B1',
    coverage_errors: [],
    reports: groups.map((g) => ({
      group_id: g.group_id,
      split: g.split,
      path: g.group_id + '/windows.json',
      longflow_path: g.group_id + '/longflow.json',
      coverage_errors: []
    }))
  };
  const audit = {
    schema: 'g03-root-conservative-analysis-release/v1',
    analysis_contract: 'r4-worst-case-benign-fp-v1',
    stage: 'B1',
    analysis_input_allowed: true,
    raw_acquisition_complete: true,
    terminal_completed: true,
    expected_groups: 71,
    observed_groups: 71,
    private_test_values_read: false,
    classifier_fitting_performed: false,
    certified_policy_issued: false,
    collector_freeze: { path: masterPath, sha256: hash(encode(master)) },
    frozen_collector_sha256: hash(encode(master)),
    observer_index: { path: indexPath, sha256: hash(encode(oldIndex)) },
    strict_audit: { path: strictPath, sha256: H(5), auditor_sha256: H(6) },
    prepared: {
      path: preparedPath,
      sha256: H(3),
      assets_checked: 1,
      binaries_checked: 2
    },
    auditor_sha256: hash(auditor),
    input_sha256: {
      [masterPath]: hash(encode(master)),
      [indexPath]: hash(encode(oldIndex)),
      [strictPath]: H(5),
      [preparedPath]: H(3)
    },
    groups: groups.map((g) => ({
      group_id: g.group_id,
      raw_acquisition_qualified: true,
      strict_acquisition_qualified: true,
      semantic_unknown: false,
      semantic_coverage_complete: true,
      primary_flow_inventory: ['fixture-flow']
    })),
    semantic_unknown_groups: [],
    semantic_coverage_complete: true,
    completion_finished_utc: '2026-01-01T02:00:00Z',
    checked_utc: '2026-01-01T02:00:01Z'
  };
  const tools = {};
  for (const name of ['observer', 'longflow']) {
    const source = 'lab/dpi-g04/' + name + '/header.go',
      binary =
        'lab/dpi-g04/' +
        name +
        '/tooling/' +
        name +
        '-g04-header-v1-darwin-arm64-123456789abc',
      bytes = Buffer.from('synthetic ' + name + ' binary'),
      code = Buffer.from('synthetic ' + name + ' source');
    map.set(path.join(root, source), code);
    map.set(path.join(root, binary), bytes);
    tools[name] = {
      schema: name === 'observer' ? 6 : 4,
      version: 'g04-header-' + name + '-v1',
      created_at: '2026-01-01T02:00:02Z',
      evidence_unit: 'tls23_header_declared_length',
      coverage_semantics_sha256: C,
      ordering_semantics_sha256: O,
      feature_definitions_sha256: name === 'longflow' ? L : undefined,
      source_sha256: { [source]: hash(code) },
      binary: { [name]: { versioned_path: binary, sha256: hash(bytes) } }
    };
  }
  const metas = {};
  for (const g of groups) {
    const dir = path.join(path.dirname(indexPath), g.group_id),
      meta = {
        group_id: g.group_id,
        split: g.split,
        class: g.class,
        profile: g.profile,
        server_ports: [443],
        capture_started_utc: '2026-01-01T01:10:00Z',
        capture_ended_utc: '2026-01-01T01:11:22Z',
        measurement_start_unix_micros:
          Date.parse('2026-01-01T01:10:00Z') * 1000,
        measured_seconds: 80,
        prefix_grace_seconds: 2,
        window_offsets_seconds: master.window_offsets_seconds,
        freeze_sha256: hash(encode(master)),
        capture_cap_hit: false,
        packets_dropped: 0,
        capture_cap_bytes: 268435456
      };
    metas[g.group_id] = meta;
    for (const [file, bytes] of [
      ['outer.pcap', pcap],
      [
        'windows.json',
        encode({
          metadata: meta,
          events: [{ OLD_EVENT_MUST_NOT_BE_ROUNDTRIPPED: 777 }]
        })
      ]
    ]) {
      const p = path.join(dir, file);
      map.set(p, bytes);
      audit.input_sha256[p] = hash(bytes);
    }
  }
  const obPath = path.join(root, 'observer-tooling.json'),
    lfPath = path.join(root, 'longflow-tooling.json');
  function sync() {
    map.set(masterPath, encode(master));
    audit.collector_freeze.sha256 = hash(encode(master));
    audit.frozen_collector_sha256 = hash(encode(master));
    audit.input_sha256[masterPath] = hash(encode(master));
    audit.observer_index.sha256 = hash(encode(oldIndex));
    audit.input_sha256[indexPath] = hash(encode(oldIndex));
    map.set(indexPath, encode(oldIndex));
    map.set(auditPath, encode(audit));
    map.set(obPath, encode(tools.observer));
    map.set(lfPath, encode(tools.longflow));
  }
  sync();
  let mono = 0;
  const isRaw = (p) =>
    p === indexPath || p.startsWith(path.dirname(indexPath) + path.sep);
  function ensureGate(p) {
    if (isRaw(p)) {
      assert.ok(
        fs.existsSync(path.join(out, 'DECLARATION.json')),
        'rawread beforedeclaration'
      );
      assert.equal(
        JSON.parse(fs.readFileSync(path.join(out, 'DECLARATION.json')))
          .read_authorized,
        true,
        'rawread withoutauthorization'
      );
    }
    assert.ok(!/sealed-test-vault/.test(p), 'vault read forbidden');
  }
  const io = {
    root,
    utc: () => '2026-01-01T02:00:03Z',
    monotonicMS: () => mono,
    readFileSync(p) {
      p = path.resolve(p);
      ensureGate(p);
      events.push({ op: 'read', path: p });
      return map.has(p) ? map.get(p) : fs.readFileSync(p);
    },
    hashFileSync(p) {
      ensureGate(p);
      events.push({ op: 'hash-raw', path: p });
      return hash(map.get(p));
    },
    writeFileSync(p, raw, opts) {
      events.push({ op: 'write', path: p });
      return fs.writeFileSync(p, raw, opts);
    },
    spawnSync(program, args, opts) {
      const pcapPath = args[args.indexOf('-pcap') + 1],
        metaPath = args[args.indexOf('-meta') + 1],
        dest = args[args.indexOf('-out') + 1];
      ensureGate(pcapPath);
      const name = program.includes('/observer/') ? 'observer' : 'longflow',
        meta = JSON.parse(fs.readFileSync(metaPath));
      assert.equal(meta.events, undefined);
      assert.ok(!JSON.stringify(meta).includes('OLD_EVENT'));
      calls.push({ name, pcapPath, metaPath, dest, opts });
      mono += 10;
      const report = {
        schema: name === 'observer' ? 6 : 4,
        version: 'g04-header-' + name + '-v1',
        evidence_unit: 'tls23_header_declared_length',
        coverage_semantics_sha256: C,
        ordering_semantics_sha256: O,
        feature_definitions_sha256: name === 'longflow' ? L : undefined,
        metadata: meta,
        pcap_sha256: hash(pcap),
        coverage_complete: meta.group_id !== groups[0].group_id,
        source_observer_coverage_complete: meta.group_id !== groups[0].group_id
      };
      fs.writeFileSync(dest, encode(report));
      return {
        status: 0,
        signal: null,
        stdout: Buffer.from('synthetic parser output'),
        stderr: Buffer.alloc(0)
      };
    }
  };
  const argv = [
    '--master',
    masterPath,
    '--audit',
    auditPath,
    '--observer-tooling',
    obPath,
    '--longflow-tooling',
    lfPath,
    '--out-dir',
    out
  ];
  return {
    root,
    out,
    map,
    master,
    audit,
    groups,
    oldIndex,
    tools,
    metas,
    pcap,
    indexPath,
    masterPath,
    auditPath,
    obPath,
    lfPath,
    events,
    calls,
    io,
    argv,
    sync,
    advance: (n) => {
      mono += n;
    },
    manifest: () =>
      JSON.parse(fs.readFileSync(path.join(out, 'EXTRACTION.json')))
  };
}
test('Default persists declaration butreads no group/index/PCAP andrunsnothing', (t) => {
  const f = fixture(t),
    r = main(f.argv, f.io);
  assert.equal(r.status, 'declaration_only');
  assert.equal(r.actual_group_or_index_or_PCAP_reads, 0);
  assert.equal(f.calls.length, 0);
  assert.equal(
    f.events.some((e) => e.op === 'hash-raw'),
    false
  );
  assert.deepEqual(fs.readdirSync(f.out), ['DECLARATION.json']);
  const d = JSON.parse(fs.readFileSync(path.join(f.out, 'DECLARATION.json')));
  assert.equal(d.read_authorized, false);
  assert.equal(d.groups.length, 71);
  assert.equal(d.posthoc_development, true);
  assert.equal(d.original_test_commitment_sha256, H(900));
  assert.throws(() => main(f.argv, f.io), /NEW_output_required_no_overwrite/);
});
test('Authorized oncepergroup derivation preserves UNKNOWN andrawindexflags without eventroundtrip', (t) => {
  const f = fixture(t),
    r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, true);
  assert.equal(r.groups, 71);
  assert.equal(f.calls.length, 142);
  assert.equal(new Set(f.calls.map((c) => c.dest)).size, 142);
  assert.equal(
    f.calls.every(
      (c) =>
        c.opts.timeout > 0 && c.opts.timeout <= 60000 && c.opts.shell === false
    ),
    true
  );
  const index = JSON.parse(
    fs.readFileSync(path.join(f.out, 'observer-index.json'))
  );
  assert.equal(index.reports.length, 71);
  assert.deepEqual(index.reports[0].coverage_errors, []);
  assert.ok(
    f.manifest().semantic_unknown_groups.includes(f.groups[0].group_id)
  );
  assert.equal(f.manifest().global_integrity, true);
  const firstRaw = f.events.findIndex((e) => e.path === f.indexPath),
    decl = f.events.findIndex(
      (e) => e.op === 'write' && e.path.endsWith('DECLARATION.json')
    );
  assert.ok(decl >= 0 && firstRaw > decl);
});
test('Incomplete/test/Q/cohort errorsreject BEFOREgroup orindexrefs opened', (t) => {
  for (const mode of ['incomplete', 'test', 'Q', 'terminal']) {
    const f = fixture(t);
    if (mode === 'incomplete') f.master.groups.pop();
    else if (mode === 'test') f.master.groups[0].split = 'test';
    else if (mode === 'Q') f.master.stage = 'Q';
    else f.audit.terminal_completed = false;
    f.sync();
    assert.throws(() => main([...f.argv, '--authorize-read'], f.io));
    assert.equal(fs.existsSync(f.out), false);
    assert.equal(
      f.events.some((e) => e.path === f.indexPath || e.op === 'hash-raw'),
      false
    );
  }
});
test('Source drift andmissing rawSHA reject without actualrawreads', (t) => {
  for (const mode of ['source', 'SHA']) {
    const f = fixture(t);
    if (mode === 'source') {
      const p = Object.keys(f.tools.observer.source_sha256)[0];
      f.map.set(path.join(f.root, p), Buffer.from('changed'));
    } else {
      delete f.audit.input_sha256[
        path.join(path.dirname(f.indexPath), f.groups[0].group_id, 'outer.pcap')
      ];
      f.sync();
    }
    assert.throws(() => main([...f.argv, '--authorize-read'], f.io));
    assert.equal(f.calls.length, 0);
    assert.equal(
      f.events.some((e) => e.op === 'hash-raw'),
      false
    );
  }
});
test('PCAP byteschanged afteraudit neverexecute andcannotauthorizefit', (t) => {
  const f = fixture(t),
    pcap = path.join(
      path.dirname(f.indexPath),
      f.groups[0].group_id,
      'outer.pcap'
    );
  f.map.set(pcap, Buffer.from('changed-PCAP'));
  const r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, false);
  assert.equal(f.calls.length, 140);
  assert.equal(f.manifest().groups[0].attempts.length, 0);
  assert.match(f.manifest().groups[0].errors[0], /audited_PCAP_changed/);
});
test('Onefailedchild isretained; companion andlatergroupsrunonce withnoretry', (t) => {
  const f = fixture(t),
    spawn = f.io.spawnSync;
  let first = true;
  f.io.spawnSync = (...args) => {
    const r = spawn(...args);
    if (first) {
      first = false;
      r.status = 7;
      r.stderr = Buffer.from('synthetic actualfailure');
    }
    return r;
  };
  const r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, false);
  assert.equal(f.calls.length, 142);
  const g = f.manifest().groups[0];
  assert.equal(g.attempts[0].status, 7);
  assert.equal(g.attempts[1].status, 0);
  assert.ok(g.errors.includes('observer:process_failed'));
});
test('60stotalgroup deadline rejects overrun andneverinvokesremaining child afterbudget', (t) => {
  const f = fixture(t),
    spawn = f.io.spawnSync;
  let first = true;
  f.io.spawnSync = (...args) => {
    const r = spawn(...args);
    if (first) {
      first = false;
      f.advance(60001);
    }
    return r;
  };
  const r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, false);
  assert.equal(f.calls.length, 141);
  const g = f.manifest().groups[0];
  assert.ok(g.errors.includes('observer:group_deadline_exceeded'));
  assert.equal(g.attempts[1].invoked, false);
  assert.equal(g.attempts[1].error, 'group_deadline_exhausted_not_started');
});
test('Pinnedmetadatafile preferred; fallbackcopies ONLYpinnedoldreportmetadata', (t) => {
  const f = fixture(t),
    g = f.groups[1],
    p = path.join(path.dirname(f.indexPath), g.group_id, 'observer-meta.json'),
    raw = encode(f.metas[g.group_id]);
  f.map.set(p, raw);
  f.audit.input_sha256[p] = hash(raw);
  f.sync();
  main([...f.argv, '--authorize-read'], f.io);
  assert.equal(
    f.manifest().groups[1].metadata_source.kind,
    'pinned_observer_metadata'
  );
  assert.equal(
    fs
      .readFileSync(path.join(f.out, g.group_id, 'observer-meta.json'))
      .equals(raw),
    true
  );
  assert.equal(
    f.events.some(
      (e) =>
        e.op === 'read' &&
        e.path ===
          path.join(path.dirname(f.indexPath), g.group_id, 'windows.json')
    ),
    false
  );
});
test('ChangedDECLARATION stopsallrawIO instead ofcontinuingundergate', (t) => {
  const f = fixture(t),
    write = f.io.writeFileSync;
  f.io.writeFileSync = (p, raw, o) => {
    const r = write(p, raw, o);
    if (p.endsWith('DECLARATION.json')) fs.appendFileSync(p, 'tampered');
    return r;
  };
  const r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, false);
  assert.equal(f.calls.length, 0);
  assert.equal(
    f.events.some((e) => e.op === 'hash-raw' || e.path === f.indexPath),
    false
  );
  assert.match(f.manifest().errors[0], /persisted_declaration_changed/);
});
test('Rawcoverageerrors copiedverbatim; semanticUNKNOWN notinjectedintothatnamespace', (t) => {
  const f = fixture(t);
  f.oldIndex.reports[1].coverage_errors = ['synthetic_raw_capture_error'];
  f.sync();
  const r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, false);
  const idx = JSON.parse(
    fs.readFileSync(path.join(f.out, 'observer-index.json'))
  );
  assert.deepEqual(idx.reports[1].coverage_errors, [
    'synthetic_raw_capture_error'
  ]);
  assert.deepEqual(idx.reports[0].coverage_errors, []);
});

test('Successfulprocess cannotclaimwrongPCAP orschema asvalidheaderoutput', (t) => {
  const f = fixture(t),
    spawn = f.io.spawnSync;
  let first = true;
  f.io.spawnSync = (...args) => {
    const r = spawn(...args);
    if (first) {
      first = false;
      const dest = args[1][args[1].indexOf('-out') + 1],
        x = JSON.parse(fs.readFileSync(dest));
      x.pcap_sha256 = H(999);
      fs.writeFileSync(dest, encode(x));
    }
    return r;
  };
  const r = main([...f.argv, '--authorize-read'], f.io);
  assert.equal(r.global_integrity, false);
  assert.equal(f.calls.length, 142);
  assert.ok(
    f
      .manifest()
      .groups[0].errors.includes('observer:new_output_view_or_PCAP_binding')
  );
});
test('Binarymutationafterexec retained withactualafterSHA andstopsuntrustedprograms', (t) => {
  const f = fixture(t),
    spawn = f.io.spawnSync;
  let first = true;
  const binary = path.join(
    f.root,
    f.tools.observer.binary.observer.versioned_path
  );
  f.io.spawnSync = (...args) => {
    const r = spawn(...args);
    if (first) {
      first = false;
      f.map.set(binary, Buffer.from('mutated executable'));
    }
    return r;
  };
  const r = main([...f.argv, '--authorize-read'], f.io),
    m = f.manifest();
  assert.equal(r.global_integrity, false);
  assert.equal(f.calls.length, 1);
  assert.equal(
    m.groups[0].attempts[0].binary_after_sha256,
    hash(Buffer.from('mutated executable'))
  );
  assert.equal(
    m.toolchain_after_sha256[binary],
    hash(Buffer.from('mutated executable'))
  );
  assert.ok(m.errors.some((e) => e.includes('toolchain_or_metadata_changed')));
});

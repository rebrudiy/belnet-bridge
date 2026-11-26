'use strict';
const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs'),
  os = require('node:os'),
  path = require('node:path');
const {
  createLedger,
  validateLedger,
  planNativeRound,
  digest
} = require('./index.cjs');
const H = (n) => n.toString(16).padStart(64, '0');
function fixture(t) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'belnet-iterations-fixture-')
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const refs = {},
    docs = {},
    order = [];
  const put = (name, obj, binary = false) => {
    const p = path.join(root, name);
    fs.writeFileSync(p, binary ? obj : JSON.stringify(obj));
    const r = { path: p, sha256: digest(fs.readFileSync(p)) };
    refs[name] = r;
    if (!binary) {
      docs[name] = obj;
      order.push(name);
    }
    return r;
  };
  const code = put('source.go', Buffer.from('package fixture\n'), true),
    code2 = put(
      'response.go',
      Buffer.from('package fixture\nvar coalesce=true\n'),
      true
    );
  const source = put('source.json', {
      kind: 'source_manifest',
      files: [{ ...code, logical_path: 'wrapper.go' }]
    }),
    source2 = put('source2.json', {
      kind: 'source_manifest',
      files: [{ ...code2, logical_path: 'wrapper.go' }]
    });
  const elfBytes = (n) => {
    const b = Buffer.alloc(64, n);
    Buffer.from([127, 69, 76, 70]).copy(b);
    return b;
  };
  const elf = put('before.elf', elfBytes(1), true),
    elf2 = put('after.elf', elfBytes(2), true);
  const proto = put('protocol.md', Buffer.from('synthetic protocol'), true),
    raw = put('raw.json', { scope: 'train_validation', synthetic: true }),
    l = createLedger(proto);
  const baseGroups = Array.from({ length: 71 }, (_, i) => ({
    group_id: 'base-' + i,
    split: i < 46 ? 'train' : 'validation',
    scope: 'primary',
    class: i < 6 || (i >= 46 && i < 49) ? 'belnet' : 'benign'
  }));
  const master = put('master.json', { stage: 'B1', groups: baseGroups }),
    index = put('base-index.json', {
      schema: 4,
      stage: 'B1',
      reports: baseGroups.map((g) => ({
        group_id: g.group_id,
        split: g.split,
        coverage_errors: []
      }))
    });
  l.baseline = put('baseline.json', {
    collector_freeze: master,
    observer_index: index,
    kind: 'healthy_primary_B1',
    healthy: true,
    groups: baseGroups,
    benign_corpus_sha256: H(1),
    measurement_contract_sha256: H(2),
    completed_at: '2026-01-01T01:00:00Z'
  });
  const policy = (threshold, frozen) => ({
    version: 'g03-ensemble-v3',
    method: 'joint OR classical',
    group_fpr_budget: 0.05,
    direct_flow_fpr_budget: 0.05,
    score_engine_sha256: elf.sha256,
    coverage_semantics_sha256: H(3),
    ordering_semantics_sha256: H(4),
    joint_group_margin: 0,
    policy_frozen_at: frozen,
    last_development_capture_ended_utc: '2026-01-01T01:04:16Z',
    rules: [
      {
        rule: { id: 'r01', definition: 'fixed classic feature' },
        enabled: true,
        threshold
      }
    ]
  });
  const p0 = put('before-policy.json', policy(10, '2026-01-01T00:59:59Z')),
    p1 = put('after-policy.json', policy(20, '2026-01-01T01:00:03Z')),
    p2 = put('last-policy.json', policy(20, '2026-01-01T01:04:17Z'));
  const feature = put('feature.json', {
    kind: 'measured_feature',
    feature: 'outer record pair',
    split: 'train',
    measurements: [{ count: 10 }],
    raw_evidence: raw,
    observed_at: '2026-01-01T01:00:01Z'
  });
  const delta = put('detector.json', {
    kind: 'classical_detector_delta',
    change_kind: 'threshold',
    changed_rule_ids: ['r01'],
    before_policy: p0,
    after_policy: p1,
    source_manifest: source,
    program: elf,
    engine: elf
  });
  const benignRows = baseGroups
    .filter((g) => g.class === 'benign')
    .map((g) => ({
      ...g,
      coverage_complete: true,
      any_detected: false,
      primary_flow_inventory: ['f1', 'f2'],
      windows: []
    }));
  const metrics = {};
  for (const split of ['train', 'validation']) {
    const n = benignRows.filter((r) => r.split === split).length;
    metrics[split] = {
      benign_groups: n,
      false_positive_groups: 0,
      group_fpr: 0,
      benign_flows: n * 2,
      direct_rule_hit_false_positive_flows: 0,
      direct_rule_hit_flow_fpr: 0
    };
  }
  const raw1 = put('benign-raw1.json', {
      stage: 'B1',
      policy_sha256: p1.sha256,
      decisions: structuredClone(benignRows),
      by_split: structuredClone(metrics)
    }),
    raw2 = put('benign-raw2.json', {
      stage: 'B1',
      policy_sha256: p2.sha256,
      decisions: structuredClone(benignRows),
      by_split: structuredClone(metrics)
    });
  const b1 = put('benign1.json', {
      kind: 'joint_benign_FP',
      aggregation: 'joint_OR_all_rules_windows_flows_reconnects',
      policy_sha256: p1.sha256,
      benign_corpus_sha256: H(1),
      evaluated_at: '2026-01-01T01:00:04Z',
      raw_report: raw1
    }),
    b2 = put('benign2.json', {
      kind: 'joint_benign_FP',
      aggregation: 'joint_OR_all_rules_windows_flows_reconnects',
      policy_sha256: p2.sha256,
      benign_corpus_sha256: H(1),
      evaluated_at: '2026-01-01T01:04:19Z',
      raw_report: raw2
    });
  const settings = put('settings.json', {
      kind: 'transport_settings',
      settings: { coalesce: false }
    }),
    settings2 = put('settings2.json', {
      kind: 'transport_settings',
      settings: { coalesce: true }
    }),
    buildRecord = put('build.json', {
      kind: 'wrapper_build',
      source_manifest_sha256: source2.sha256,
      elf_sha256: elf2.sha256,
      started_at: '2026-01-01T01:00:05Z',
      completed_at: '2026-01-01T01:00:06Z'
    });
  const wrapper = put('wrapper.json', {
    kind: 'transport_wrapper_change',
    selected_at: '2026-01-01T01:00:05Z',
    before: { source_manifest: source, elf, settings },
    after: { source_manifest: source2, elf: elf2, settings: settings2 },
    build_record: buildRecord
  });
  const times = [
      ['01:00:08', '01:01:30'],
      ['01:01:31', '01:02:53'],
      ['01:02:54', '01:04:16']
    ],
    groups = ['rpc', 'download', 'upload'].map((family, i) => ({
      group_id: 'fresh-' + i,
      split: i === 1 ? 'validation' : 'train',
      scope: 'primary',
      class: 'belnet',
      experiment_role: 'candidate-development',
      family,
      fresh_identity: true,
      identity_sha256: H(100 + i),
      capture_complete: true,
      native_process_verified: true,
      native_udp_inputs: 10,
      capture_started_at: '2026-01-01T' + times[i][0] + 'Z',
      capture_ended_at: '2026-01-01T' + times[i][1] + 'Z',
      raw_sources: [raw, raw, raw],
      nonce_results: [
        'initial',
        'warmup-0',
        'warmup-1',
        'warmup-2',
        'main'
      ].map((label, j) => ({
        label,
        nonce: H(1000 + i * 5 + j),
        status: j ? 'success' : 'failed',
        service_nonce: j ? H(1000 + i * 5 + j) : null,
        client_bytes: j ? 100 : 0,
        server_bytes: j ? 100 : 0,
        error: j ? null : 'cold DNS refused'
      }))
    }));
  const native = put('native.json', {
    kind: 'fresh_native_development',
    wrapper_elf_sha256: elf2.sha256,
    wrapper_source_sha256: source2.sha256,
    wrapper_settings_sha256: settings2.sha256,
    measurement_contract_sha256: H(2),
    max_native_concurrent: 1,
    frozen_at: '2026-01-01T01:00:07Z',
    groups
  });
  const attackRaw = put('attack-raw.json', {
    stage: 'B1',
    policy_sha256: p2.sha256,
    decisions: groups.map((g, i) => ({
      group_id: g.group_id,
      split: g.split,
      class: 'belnet',
      scope: 'primary',
      coverage_complete: true,
      any_detected: i === 1,
      abstained: false
    }))
  });
  const attack = put('attack.json', {
    kind: 'classical_shadow_retest',
    scope: 'development_train_validation',
    live_enforcement: false,
    policy: p2,
    source_manifest: source,
    program: elf,
    engine: elf,
    evaluated_at: '2026-01-01T01:04:18Z',
    raw_report: attackRaw
  });
  const cost = put('cost.json', {
    kind: 'native_cost_measurements',
    wrapper_elf_sha256: elf2.sha256,
    measured_at: '2026-01-01T01:04:20Z',
    groups: groups.map((g) => ({
      group_id: g.group_id,
      bytes: { application: 100, outer_wire: 180 },
      loss: {
        definition: 'bridge_udp_input_to_forward_write',
        inputs: 10,
        forwarded: 10,
        expired: 0,
        dropped: 0,
        failed: 0,
        unknown: 0
      },
      latency: {
        clock: 'linux-vm',
        definition: 'input_to_write_start',
        status: 'measured',
        samples: 10,
        p50_ms: 1,
        p95_ms: 3,
        max_ms: 4
      },
      raw_sources: [raw]
    }))
  });
  const evidence = put('evidence.json', {
    kind: 'measured_classical_transport_pair',
    origin: 'synthetic_fixture',
    feature,
    detector_delta: delta,
    benign_initial: b1,
    wrapper_build: wrapper,
    native_proof: native,
    last_attack: attack,
    benign_final: b2,
    cost
  });
  l.cycles[0] = {
    cycle: 1,
    state: 'complete',
    hypothesis: {
      kind: 'adaptive_classical_transport',
      measured_feature: 'outer record pair',
      selected_at: '2026-01-01T01:00:02Z',
      parent_result_sha256: l.baseline.sha256
    },
    evidence,
    decision: {
      outcome: 'accepted',
      reason: 'synthetic fixture, not a measured real improvement',
      closed_at: '2026-01-01T01:04:21Z'
    }
  };
  function refresh() {
    for (const name of order) {
      if (name === 'benign-raw1.json' || name === 'benign1.json')
        docs[name].policy_sha256 = refs['after-policy.json'].sha256;
      if (
        name === 'benign-raw2.json' ||
        name === 'benign2.json' ||
        name === 'attack-raw.json'
      )
        docs[name].policy_sha256 = refs['last-policy.json'].sha256;
      fs.writeFileSync(refs[name].path, JSON.stringify(docs[name]));
      refs[name].sha256 = digest(fs.readFileSync(refs[name].path));
    }
  }
  return {
    l,
    root,
    docs,
    refs,
    refresh,
    options: { root, allowSynthetic: true },
    validate() {
      return validateLedger(l, { root, allowSynthetic: true });
    }
  };
}

test('G04 header-based classical policies preserve the full measured-pair contract', t => {
  const f = fixture(t);
  for (const name of ['before-policy.json', 'after-policy.json', 'last-policy.json']) f.docs[name].version = 'g04-header-ensemble-v1';
  f.refresh();
  const r = f.validate();
  assert.equal(r.validated_complete_rows, 1);
  assert.equal(r.actual_complete_cycles, 0);
  f.docs['after-policy.json'].version = 'g04-header-auxiliary-ml-v1';
  f.refresh();
  assert.throws(() => f.validate(), /CLASSICAL_POLICY_REQUIRED/);
});
test('All15pending rows count0 and open no evidence files', () => {
  const l = createLedger({ path: 'protocol.md', sha256: H(1) });
  const r = validateLedger(l, {
    readFileSync() {
      throw Error('unexpectedread');
    }
  });
  assert.equal(r.actual_complete_cycles, 0);
  assert.equal(r.pending, 15);
  assert.equal(r.fifteen_actual_cycles_complete, false);
});
test('Complete synthetic chain validates but never counts as real iteration', (t) => {
  const f = fixture(t),
    r = f.validate();
  assert.equal(r.validated_complete_rows, 1);
  assert.equal(r.actual_complete_cycles, 0);
  assert.equal(r.results[0].shadow_detected_groups, 1);
  assert.equal(r.results[0].all_main_nonce_success, true);
  assert.throws(
    () => validateLedger(f.l, { root: f.root }),
    /ACTUAL_MEASUREMENTS_REQUIRED/
  );
});
test('Complete flag without artifacts cannot fabricate a cycle', () => {
  const l = createLedger({ path: 'protocol.md', sha256: H(1) });
  l.cycles[0].state = 'complete';
  assert.throws(() => validateLedger(l), /MEASURED_DECISION_REQUIRED/);
});
test('Later hypotheses cannot be preplanned before prior actual outcome', () => {
  const l = createLedger({ path: 'protocol.md', sha256: H(1) });
  l.cycles[1].state = 'in_progress';
  assert.throws(
    () => validateLedger(l),
    /ADAPTATION_REQUIRES_PREVIOUS_COMPLETE/
  );
  l.cycles[1].state = 'pending';
  l.cycles[1].hypothesis = { feature: 'guess' };
  assert.throws(() => validateLedger(l), /PENDING_HAS_NO_PREPLANNED_RESULTS/);
});
test('ML policy or capture repair is not a classical cycle', (t) => {
  for (const mode of ['ML', 'capture']) {
    const f = fixture(t);
    if (mode === 'ML')
      f.docs['after-policy.json'].version = 'g03-auxiliary-ml-v2';
    else f.docs['detector.json'].kind = 'capture_repair';
    f.refresh();
    assert.throws(() => f.validate());
  }
});
test('Timestamp/description-only detector change is not a semantic delta', (t) => {
  const f = fixture(t);
  f.docs['after-policy.json'].rules[0].threshold = 10;
  f.docs['after-policy.json'].rules[0].rule.definition = 'newprose';
  f.refresh();
  assert.throws(() => f.validate(), /NO_DETECTOR_SEMANTIC_DELTA/);
});
test('Changed capture/ordering ABI cannot be claimed as a cycle', (t) => {
  const f = fixture(t);
  f.docs['after-policy.json'].coverage_semantics_sha256 = H(999);
  f.refresh();
  assert.throws(() => f.validate(), /CAPTURE_ABI_REPAIR_NOT_A_CYCLE/);
});
test('Benign denominator shrink or invented FP ratios are rejected', (t) => {
  for (const mode of ['shrink', 'ratio']) {
    const f = fixture(t);
    if (mode === 'shrink') f.docs['benign-raw1.json'].decisions.pop();
    else f.docs['benign-raw1.json'].by_split.train.group_fpr = 0.9;
    f.refresh();
    assert.throws(() => f.validate());
  }
});
test('Missing native family or test split cannot complete', (t) => {
  for (const mode of ['family', 'test']) {
    const f = fixture(t);
    if (mode === 'family') f.docs['native.json'].groups[2].family = 'rpc';
    else f.docs['native.json'].groups[0].split = 'test';
    f.refresh();
    assert.throws(() => f.validate());
  }
});
test('Native source/ELF pin mismatch and repeatedidentity reject', (t) => {
  for (const mode of ['elf', 'identity']) {
    const f = fixture(t);
    if (mode === 'elf') f.docs['native.json'].wrapper_elf_sha256 = H(999);
    else
      f.docs['native.json'].groups[1].identity_sha256 =
        f.docs['native.json'].groups[0].identity_sha256;
    f.refresh();
    assert.throws(() => f.validate());
  }
});
test('UNKNOWN capture cannot become completed bypass evidence', (t) => {
  const f = fixture(t);
  f.docs['native.json'].groups[0].capture_complete = false;
  f.refresh();
  assert.throws(() => f.validate(), /FRESH_NATIVE_INPUT_AND_CAPTURE_REQUIRED/);
});
test('Nonce or service proof mismatch cannot complete', (t) => {
  const f = fixture(t);
  f.docs['native.json'].groups[0].nonce_results[4].server_bytes = 99;
  f.refresh();
  assert.throws(() => f.validate(), /SERVICE_NONCE_PROOF_MISMATCH/);
});
test('Strong classical attacker must freeze after the fresh native capture', (t) => {
  const f = fixture(t);
  f.docs['last-policy.json'].policy_frozen_at = '2026-01-01T01:04:15Z';
  f.refresh();
  assert.throws(() => f.validate(), /ADAPTIVE_ATTACKER_MUST_ACT_LAST/);
});
test('Missing latency or unaccounted loss cannot complete', (t) => {
  for (const mode of ['latency', 'loss']) {
    const f = fixture(t);
    if (mode === 'latency') f.docs['cost.json'].groups[0].latency.p95_ms = null;
    else f.docs['cost.json'].groups[0].loss.unknown = 1;
    f.refresh();
    assert.throws(() => f.validate());
  }
});
test('Rejected measured variant remains a completed attempt without claiming success', (t) => {
  const f = fixture(t);
  f.l.cycles[0].decision.outcome = 'rejected';
  f.l.cycles[0].decision.reason = 'still detected';
  const r = f.validate();
  assert.equal(r.rejected, 1);
  assert.equal(r.accepted, 0);
  assert.equal(r.actual_complete_cycles, 0);
});
test('Actual artifact hash mismatch cannot be hidden by manifest flags', (t) => {
  const f = fixture(t);
  fs.appendFileSync(f.refs['after.elf'].path, 'tamper');
  assert.throws(() => f.validate(), /ARTIFACT_SHA_MISMATCH/);
});
test('Planner emits onlycurrent cycle native train/validation, allfamilies, one-at-time', () => {
  const l = createLedger({ path: 'protocol.md', sha256: H(1) });
  l.baseline = { path: 'baseline.json', sha256: H(2) };
  l.cycles[0] = {
    cycle: 1,
    state: 'in_progress',
    hypothesis: {
      kind: 'adaptive_classical_transport',
      measured_feature: 'flow lengths',
      selected_at: '2026-01-01T00:00:00Z',
      parent_result_sha256: H(2)
    },
    evidence: null,
    decision: null
  };
  let n = 100;
  const p = planNativeRound(
    l,
    1,
    {
      source_manifest: { path: 'src.json', sha256: H(3) },
      elf: { path: 'wrapper.elf', sha256: H(4) },
      build_record: { path: 'build.json', sha256: H(5) }
    },
    { seedFor: () => 123, nonceFor: () => H(n++) }
  );
  assert.equal(p.groups.length, 6);
  assert.equal(
    p.stages.B1.batches.every((b) => b.length === 1),
    true
  );
  assert.equal(new Set(p.groups.map((g) => g.family)).size, 3);
  assert.equal(
    p.groups.every(
      (g) =>
        g.scope === 'primary' &&
        g.experiment_role === 'candidate-development' &&
        ['train', 'validation'].includes(g.split) &&
        g.class === 'belnet'
    ),
    true
  );
  assert.equal(p.real_traffic_started, false);
  assert.equal(p.test_rows, 0);
});

test('Baseline raw index UNKNOWN cannot be hidden by healthy:true', (t) => {
  const f = fixture(t);
  f.docs['base-index.json'].reports[0].coverage_errors = [
    'missing_final_stats'
  ];
  f.refresh();
  f.l.cycles[0].hypothesis.parent_result_sha256 = f.l.baseline.sha256;
  assert.throws(() => f.validate(), /BASELINE_CAPTURE_NOT_HEALTHY/);
});
test('A prepared binary can be selected adaptively later without inventing a new build', (t) => {
  const f = fixture(t);
  f.docs['build.json'].started_at = '2026-01-01T00:59:00Z';
  f.docs['build.json'].completed_at = '2026-01-01T00:59:10Z';
  f.refresh();
  assert.equal(f.validate().validated_complete_rows, 1);
  f.docs['wrapper.json'].selected_at = '2026-01-01T01:00:01Z';
  f.refresh();
  assert.throws(
    () => f.validate(),
    /WRAPPER_SELECTION_PRECEDED_DPI_MEASUREMENT/
  );
});
test('A real joint group FP excess blocks acceptance but remains a rejected measured cycle', (t) => {
  const f = fixture(t),
    r = f.docs['benign-raw2.json'];
  for (const d of r.decisions.filter((x) => x.split === 'train').slice(0, 3)) {
    d.any_detected = true;
    d.windows = [{ flow_id: 'f1', hits: ['r01'] }];
  }
  Object.assign(r.by_split.train, {
    false_positive_groups: 3,
    group_fpr: 3 / 40,
    direct_rule_hit_false_positive_flows: 3,
    direct_rule_hit_flow_fpr: 3 / 80
  });
  f.refresh();
  assert.throws(() => f.validate(), /FAILED_VARIANT_CANNOT_BE_ACCEPTED/);
  f.l.cycles[0].decision.outcome = 'rejected';
  f.l.cycles[0].decision.reason = 'joint FP budget failed';
  assert.equal(f.validate().results[0].benign_final_within_budget, false);
});
function addEngineered(p, upper) {
  p.rules[0].threshold = 10;
  p.rules.push(
    {
      rule: { id: 'r02', definition: 'second fixed feature' },
      enabled: true,
      threshold: 10
    },
    {
      rule: { id: 'a01', definition: 'human narrative only' },
      enabled: true,
      threshold: 0.5
    }
  );
  p.engineered_rules = [
    {
      id: 'a01',
      name: 'label',
      hypothesis: 'story',
      development_evidence_sha256: H(44),
      terms: [
        { source: 'r01', shape: 'high', lower: 0, upper },
        { source: 'r02', shape: 'low', lower: 0, upper: 1 }
      ]
    }
  ];
}
test('Engineered formula terms count; description or evidence SHA alone does not', (t) => {
  const f = fixture(t);
  for (const n of [
    'before-policy.json',
    'after-policy.json',
    'last-policy.json'
  ])
    addEngineered(f.docs[n], 1);
  f.docs['detector.json'].change_kind = 'rule';
  f.docs['detector.json'].changed_rule_ids = ['a01'];
  f.docs['after-policy.json'].engineered_rules[0].name = 'newname';
  f.docs['after-policy.json'].engineered_rules[0].development_evidence_sha256 =
    H(99);
  f.refresh();
  assert.throws(() => f.validate(), /NO_DETECTOR_SEMANTIC_DELTA/);
  f.docs['after-policy.json'].engineered_rules[0].terms[0].upper = 0.8;
  f.docs['last-policy.json'].engineered_rules[0].terms[0].upper = 0.8;
  f.refresh();
  assert.equal(f.validate().validated_complete_rows, 1);
});

test('Planner rejects nonce reuse and never plans later pendingcycles', () => {
  const l = createLedger({ path: 'protocol.md', sha256: H(1) });
  l.baseline = { path: 'baseline.json', sha256: H(2) };
  l.cycles[0] = {
    cycle: 1,
    state: 'in_progress',
    hypothesis: {
      kind: 'adaptive_classical_transport',
      measured_feature: 'feature',
      selected_at: '2026-01-01T00:00:00Z',
      parent_result_sha256: H(2)
    },
    evidence: null,
    decision: null
  };
  const c = {
    source_manifest: { path: 'src.json', sha256: H(3) },
    elf: { path: 'a.elf', sha256: H(4) },
    build_record: { path: 'build.json', sha256: H(5) }
  };
  assert.throws(
    () => planNativeRound(l, 1, c, { nonceFor: () => H(8) }),
    /FRESH_UNIQUE_NONCE_REQUIRED/
  );
  assert.throws(
    () => planNativeRound(l, 2, c),
    /CURRENT_IN_PROGRESS_CYCLE_REQUIRED/
  );
});

test('Explicit INCONCLUSIVE joint FP retains actual rejected attempt without certification', (t) => {
  const f = fixture(t);
  Object.assign(f.docs['baseline.json'], {
    kind: 'completed_primary_B1',
    healthy: false,
    acquisition_complete: true,
    analysis_status: 'INCONCLUSIVE'
  });
  f.docs['base-index.json'].reports[8].coverage_errors = ['partial_TLS'];
  f.docs['benign-raw2.json'].decisions[0].coverage_complete = false;
  f.docs['benign2.json'].certification = 'INCONCLUSIVE';
  f.refresh();
  f.l.cycles[0].hypothesis.parent_result_sha256 = f.l.baseline.sha256;
  assert.throws(() => f.validate(), /FAILED_VARIANT_CANNOT_BE_ACCEPTED/);
  f.l.cycles[0].decision.outcome = 'rejected';
  f.l.cycles[0].decision.reason = 'uncertainty prevents joint FP certification';
  const r = f.validate().results[0];
  assert.equal(r.benign_final_status, 'INCONCLUSIVE');
  assert.equal(r.benign_final_within_budget, false);
  assert.deepEqual(r.benign_unknown_groups, ['base-6']);
  delete f.docs['benign2.json'].certification;
  f.refresh();
  assert.throws(() => f.validate(), /BENIGN_UNKNOWN_REQUIRES_INCONCLUSIVE/);
});

// Same declared population as strict fixtures: validation has22 benign groups.
function worstCaseFixture(t, unknownCount = 1, overlapHit = false) {
  const f = fixture(t),
    contract = 'r4-worst-case-benign-fp-v1';
  for (const name of [
    'before-policy.json',
    'after-policy.json',
    'last-policy.json'
  ])
    f.docs[name].analysis_contract = contract;
  for (const name of ['benign1.json', 'benign2.json'])
    f.docs[name].analysis_contract = contract;
  Object.assign(f.docs['baseline.json'], {
    kind: 'completed_primary_B1',
    healthy: false,
    acquisition_complete: true,
    analysis_status: 'INCONCLUSIVE'
  });
  const raw = f.docs['benign-raw2.json'],
    unknown = raw.decisions
      .filter((r) => r.split === 'validation')
      .slice(0, unknownCount);
  for (const name of ['benign-raw1.json', 'benign-raw2.json'])
    for (const r of f.docs[name].decisions) {
      r.uncertainty_bounded = true;
      r.potentially_affected_primary_flows = [];
    }
  for (const r of unknown) {
    r.coverage_complete = false;
    r.potentially_affected_primary_flows = ['f1'];
    f.docs['base-index.json'].reports.find(
      (x) => x.group_id === r.group_id
    ).coverage_errors = ['partial_TLS'];
  }
  if (overlapHit) {
    unknown[0].any_detected = true;
    unknown[0].windows = [{ flow_id: 'f1', hits: ['r01'] }];
  }
  function metrics() {
    for (const name of ['benign-raw1.json', 'benign-raw2.json'])
      for (const split of ['train', 'validation']) {
        const report = f.docs[name],
          rows = report.decisions.filter((r) => r.split === split),
          m = report.by_split[split],
          hits = new Set(),
          affected = new Set(),
          groups = new Set();
        for (const r of rows) {
          if (r.any_detected || !r.coverage_complete) groups.add(r.group_id);
          if (!r.coverage_complete)
            for (const id of r.potentially_affected_primary_flows)
              affected.add(r.group_id + '/' + id);
          for (const w of r.windows)
            if (w.hits.length) hits.add(r.group_id + '/' + w.flow_id);
        }
        Object.assign(m, {
          false_positive_groups: rows.filter((r) => r.any_detected).length,
          direct_rule_hit_false_positive_flows: hits.size,
          worst_case_false_positive_groups: groups.size,
          worst_case_group_fpr: groups.size / m.benign_groups,
          worst_case_direct_rule_hit_false_positive_flows: new Set([
            ...hits,
            ...affected
          ]).size,
          unbounded_benign_inventory_groups: rows.filter(
            (r) => !r.coverage_complete && !r.uncertainty_bounded
          ).length,
          incomplete_benign_potential_false_positive_groups: rows.filter(
            (r) => !r.coverage_complete
          ).length
        });
        m.group_fpr = m.false_positive_groups / m.benign_groups;
        m.direct_rule_hit_flow_fpr = hits.size / m.benign_flows;
        m.worst_case_direct_flow_fpr = m.unbounded_benign_inventory_groups
          ? null
          : m.worst_case_direct_rule_hit_false_positive_flows / m.benign_flows;
      }
    f.refresh();
    f.l.cycles[0].hypothesis.parent_result_sha256 = f.l.baseline.sha256;
  }
  metrics();
  return { ...f, unknown, metrics };
}
test('R4 bounded1unknown/22 can certify withinjoint group andactualflow5% budgets', (t) => {
  const f = worstCaseFixture(t);
  const r = f.validate().results[0];
  assert.equal(r.benign_final_status, 'CERTIFIED');
  assert.equal(r.benign_final_within_budget, true);
  assert.equal(r.benign_final_worst_case.validation.worst_case_FP, 1);
  assert.equal(r.benign_final_worst_case.validation.worst_case_FPR, 1 / 22);
  assert.equal(r.benign_final_worst_case.validation.worst_case_FP_flows, 1);
  assert.equal(
    f.docs['benign-raw2.json'].decisions.find(
      (d) => d.group_id === f.unknown[0].group_id
    ).coverage_complete,
    false
  );
});
test('R4 bounded2unknown/22 cannot beaccepted but measuredrejection remainsINCONCLUSIVE', (t) => {
  const f = worstCaseFixture(t, 2);
  assert.throws(() => f.validate(), /FAILED_VARIANT_CANNOT_BE_ACCEPTED/);
  f.l.cycles[0].decision.outcome = 'rejected';
  f.l.cycles[0].decision.reason = 'uncertainty floor2/22 exceeds5%';
  const r = f.validate().results[0];
  assert.equal(r.benign_final_status, 'INCONCLUSIVE');
  assert.equal(r.benign_final_worst_case.validation.worst_case_FP, 2);
});
test('R4 same unknown+observedhit group andphysicalflow countonce', (t) => {
  const f = worstCaseFixture(t, 1, true),
    r = f.validate().results[0],
    v = r.benign_final_worst_case.validation;
  assert.equal(v.observed_FP, 1);
  assert.equal(v.unknown, 1);
  assert.equal(v.worst_case_FP, 1);
  assert.equal(v.worst_case_FP_flows, 1);
  assert.equal(r.benign_final_status, 'CERTIFIED');
});
test('R4 affectedflowoutside frozen primaryinventory isrejected', (t) => {
  const f = worstCaseFixture(t);
  f.unknown[0].potentially_affected_primary_flows = ['invented-flow'];
  f.metrics();
  assert.throws(() => f.validate(), /AFFECTED_FLOW_OUTSIDE_INVENTORY/);
});
test('R4 unbounded inventory cannot certify orreplace null worstflowFPR with0', (t) => {
  const f = worstCaseFixture(t);
  f.unknown[0].uncertainty_bounded = false;
  f.metrics();
  assert.throws(() => f.validate(), /FAILED_VARIANT_CANNOT_BE_ACCEPTED/);
  f.l.cycles[0].decision.outcome = 'rejected';
  assert.equal(f.validate().results[0].benign_final_status, 'INCONCLUSIVE');
  f.docs['benign-raw2.json'].by_split.validation.worst_case_direct_flow_fpr = 0;
  f.refresh();
  assert.throws(() => f.validate(), /WORST_CASE_FLOW_RATIO_INCORRECT/);
});
test('R4 forgedworstcasecount or missing policycontract cannot certify', (t) => {
  const f = worstCaseFixture(t);
  f.docs[
    'benign-raw2.json'
  ].by_split.validation.worst_case_false_positive_groups = 0;
  f.refresh();
  assert.throws(() => f.validate(), /WORST_CASE_FP_METRICS_DISAGREE/);
  f.metrics();
  delete f.docs['benign2.json'].analysis_contract;
  f.refresh();
  assert.throws(() => f.validate(), /WORST_CASE_FP_CONTRACT_REQUIRED/);
});

test('Strict policies cannot silently adopt worst-case certification via evidence metadata', (t) => {
  const f = worstCaseFixture(t);
  delete f.docs['last-policy.json'].analysis_contract;
  f.refresh();
  assert.throws(() => f.validate(), /WORST_CASE_POLICY_CONTRACT_REQUIRED/);
});

function hostMachO() {
  const b = Buffer.alloc(128);
  b.writeUInt32LE(0xfeedfacf, 0); b.writeUInt32LE(0x0100000c, 4);
  b.writeUInt32LE(2, 12); b.writeUInt32LE(1, 16); b.writeUInt32LE(72, 20);
  b.writeUInt32LE(0x19, 32); b.writeUInt32LE(72, 36);
  return b;
}
function setHostDetector(f, binary) {
  const p = path.join(f.root, 'host-detector'); fs.writeFileSync(p, binary);
  const r = {path:p, sha256:digest(binary)};
  for (const name of ['detector.json', 'attack.json']) {
    f.docs[name].program = r; f.docs[name].engine = r;
  }
  for (const name of ['before-policy.json', 'after-policy.json', 'last-policy.json'])
    f.docs[name].score_engine_sha256 = r.sha256;
  f.refresh();
}
test('Actual host detector may be ARM64 Mach-O while deployed wrappers remain ELF', t => {
  const f = fixture(t); setHostDetector(f, hostMachO());
  assert.equal(f.validate().validated_complete_rows, 1);
  const ref = f.refs['before.elf']; fs.writeFileSync(ref.path, hostMachO());
  ref.sha256 = digest(hostMachO()); f.refresh();
  assert.throws(() => f.validate(), /ACTUAL_ELF_REQUIRED/);
});
test('Detector format guard rejects truncated, wrong-architecture and non-executable Mach-O', t => {
  for (const mode of ['truncated','cpu','dylib','commands']) {
    const f = fixture(t); let b = hostMachO();
    if (mode === 'truncated') b = b.subarray(0, 24);
    if (mode === 'cpu') b.writeUInt32LE(0x01000007, 4);
    if (mode === 'dylib') b.writeUInt32LE(6, 12);
    if (mode === 'commands') b.writeUInt32LE(4096, 20);
    setHostDetector(f, b);
    assert.throws(() => f.validate(), /ACTUAL_DETECTOR_EXECUTABLE_REQUIRED/);
  }
});
test('Complete bounded Go nil affected-flow slices are empty without rewriting raw evidence', t => {
  const f = worstCaseFixture(t);
  for (const name of ['benign-raw1.json','benign-raw2.json'])
    for (const d of f.docs[name].decisions)
      if (d.coverage_complete && d.uncertainty_bounded) d.potentially_affected_primary_flows = null;
  f.refresh();
  assert.equal(f.validate().validated_complete_rows, 1);
  assert(f.docs['benign-raw2.json'].decisions.some(d=>d.potentially_affected_primary_flows===null));
});
test('Mach-O detector requires an exact bounded load-command table', t => {
  for (const mode of ['count','zero','overflow','short-end','unaligned']) {
    const f = fixture(t), b = hostMachO();
    if (mode === 'count') b.writeUInt32LE(100000,16);
    if (mode === 'zero') b.writeUInt32LE(0,36);
    if (mode === 'overflow') b.writeUInt32LE(4096,36);
    if (mode === 'short-end') b.writeUInt32LE(64,36);
    if (mode === 'unaligned') b.writeUInt32LE(71,36);
    setHostDetector(f,b);
    assert.throws(()=>f.validate(), /ACTUAL_DETECTOR_EXECUTABLE_REQUIRED/);
  }
});
test('Incomplete decisions cannot replace their affected-flow inventory with null', t => {
  const f = worstCaseFixture(t);
  f.unknown[0].potentially_affected_primary_flows = null;
  f.refresh();
  assert.throws(()=>f.validate(), /BOUNDED_FLOW_INVENTORY_REQUIRED/);
});

'use strict';
// Offline evidence ledger/planner. No Docker, networking, fitting or test-vault API.
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const SHA = /^[a-f0-9]{64}$/,
  NONCE = SHA,
  WORKLOADS = ['rpc', 'download', 'upload'];
const canonical = (x) =>
  x === null || typeof x !== 'object'
    ? JSON.stringify(x)
    : Array.isArray(x)
      ? '[' + x.map(canonical).join(',') + ']'
      : '{' +
        Object.keys(x)
          .sort()
          .map((k) => JSON.stringify(k) + ':' + canonical(x[k]))
          .join(',') +
        '}';
const digest = (x) =>
  crypto
    .createHash('sha256')
    .update(Buffer.isBuffer(x) ? x : Buffer.from(canonical(x)))
    .digest('hex');
function need(x, code) {
  if (!x) throw Error(code);
}
function time(s) {
  const n = Date.parse(s);
  need(
    typeof s === 'string' && s.endsWith('Z') && Number.isFinite(n),
    'UTC_REQUIRED'
  );
  return n;
}
function ref(r) {
  need(
    r && typeof r.path === 'string' && SHA.test(r.sha256 || ''),
    'PINNED_ARTIFACT_REQUIRED'
  );
  need(
    !/vault|sealed[-_]|(?:^|[\\/])b-test-|(?:^|[\\/])b2(?:[\\/]|$)/i.test(
      r.path
    ),
    'TEST_ARTIFACT_FORBIDDEN'
  );
  return r;
}
function rowDigest(row) {
  return digest(row);
}
function createLedger(protocol) {
  return {
    schema: 'belnet-adaptive-classical-ledger/v1',
    protocol: ref(protocol),
    scope: 'train_validation_only',
    count: 15,
    budgets: {
      group_fpr: 0.05,
      direct_flow_fpr: 0.05,
      max_native_per_cycle: 6,
      max_native_concurrent: 1
    },
    baseline: null,
    cycles: Array.from({ length: 15 }, (_, i) => ({
      cycle: i + 1,
      state: 'pending',
      hypothesis: null,
      evidence: null,
      decision: null
    })),
    post_iterations: {
      refactoring: 'pending',
      last_adaptive_response: 'pending',
      B2: 'sealed'
    }
  };
}
function preflight(ledger) {
  need(
    ledger?.schema === 'belnet-adaptive-classical-ledger/v1' &&
      ledger.scope === 'train_validation_only' &&
      ledger.count === 15 &&
      ledger.cycles?.length === 15,
    'LEDGER_CONTRACT'
  );
  need(
    ledger.budgets?.group_fpr === 0.05 &&
      ledger.budgets?.direct_flow_fpr === 0.05 &&
      ledger.budgets?.max_native_per_cycle === 6 &&
      ledger.budgets?.max_native_concurrent === 1,
    'FIXED_BUDGETS_REQUIRED'
  );
  ref(ledger.protocol);
  let priorComplete = true,
    active = 0;
  ledger.cycles.forEach((r, i) => {
    need(
      r.cycle === i + 1 &&
        ['pending', 'in_progress', 'complete'].includes(r.state),
      'CYCLE_SEQUENCE'
    );
    if (r.state === 'pending') {
      need(
        r.hypothesis === null && r.evidence === null && r.decision === null,
        'PENDING_HAS_NO_PREPLANNED_RESULTS'
      );
      priorComplete = false;
      return;
    }
    need(priorComplete, 'ADAPTATION_REQUIRES_PREVIOUS_COMPLETE');
    if (r.state === 'in_progress') {
      active++;
      priorComplete = false;
      need(r.decision === null, 'UNMEASURED_DECISION');
    } else {
      need(
        r.evidence &&
          r.decision &&
          ['accepted', 'rejected'].includes(r.decision.outcome) &&
          typeof r.decision.reason === 'string' &&
          r.decision.reason.length > 0,
        'MEASURED_DECISION_REQUIRED'
      );
      ref(r.evidence);
    }
    need(
      r.hypothesis?.kind === 'adaptive_classical_transport' &&
        typeof r.hypothesis.measured_feature === 'string' &&
        r.hypothesis.measured_feature.length > 0,
      'CLASSICAL_TRANSPORT_HYPOTHESIS_REQUIRED'
    );
    need(
      SHA.test(r.hypothesis.parent_result_sha256 || '') &&
        r.hypothesis.parent_result_sha256 ===
          (i === 0 ? ledger.baseline?.sha256 : rowDigest(ledger.cycles[i - 1])),
      'ADAPTIVE_PARENT_MISMATCH'
    );
    time(r.hypothesis.selected_at);
    if (i > 0)
      need(
        time(r.hypothesis.selected_at) >
          time(ledger.cycles[i - 1].decision.closed_at),
        'HYPOTHESIS_PRECEDED_PARENT_RESULT'
      );
  });
  need(active <= 1, 'ONE_ACTIVE_CYCLE');
}
function validateLedger(
  ledger,
  {
    root = process.cwd(),
    readFileSync = fs.readFileSync,
    allowSynthetic = false
  } = {}
) {
  preflight(ledger);
  const inputSHA = {},
    identities = new Set(),
    groupIDs = new Set(),
    nonces = new Set();
  const bytes = (r) => {
    ref(r);
    const p = path.resolve(root, r.path),
      b = Buffer.from(readFileSync(p));
    need(digest(b) === r.sha256, 'ARTIFACT_SHA_MISMATCH');
    inputSHA[p] = r.sha256;
    return b;
  };
  const json = (r) => JSON.parse(bytes(r).toString());
  const sources = (r) => {
    const s = json(r);
    need(
      s.kind === 'source_manifest' &&
        Array.isArray(s.files) &&
        s.files.length > 0,
      'SOURCE_MANIFEST_REQUIRED'
    );
    for (const f of s.files) bytes(f);
    return s;
  };
  const elf = (r) => {
    const b = bytes(r);
    need(
      b.length >= 20 && b.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])),
      'ACTUAL_ELF_REQUIRED'
    );
  };
  const detectorExecutable = (r) => {
    const b = bytes(r);
    const isELF = b.length >= 20 && b.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70]));
    let isMachO = b.length >= 32 && b.readUInt32LE(0) === 0xfeedfacf &&
      b.readUInt32LE(4) === 0x0100000c && b.readUInt32LE(12) === 2 &&
      b.readUInt32LE(16) > 0 && b.readUInt32LE(20) >= 8 &&
      32 + b.readUInt32LE(20) <= b.length;
    if (isMachO) {
      const commands = b.readUInt32LE(16), end = 32 + b.readUInt32LE(20);
      let offset = 32;
      isMachO = commands <= b.readUInt32LE(20) / 8;
      for (let i = 0; isMachO && i < commands; i++) {
        if (offset + 8 > end) { isMachO = false; break; }
        const size = b.readUInt32LE(offset + 4);
        if (size < 8 || size % 8 !== 0 || offset + size > end) { isMachO = false; break; }
        offset += size;
      }
      isMachO &&= offset === end;
    }
    need(isELF || isMachO, 'ACTUAL_DETECTOR_EXECUTABLE_REQUIRED');
  };
  const classic = (r) => {
    const p = json(r);
    need(
      /^(?:g03-ensemble|g04-header-ensemble)-v\d+$/.test(p.version || '') &&
        !p.model &&
        Array.isArray(p.rules) &&
        p.rules.length > 0,
      'CLASSICAL_POLICY_REQUIRED'
    );
    need(
      p.group_fpr_budget === 0.05 && p.direct_flow_fpr_budget === 0.05,
      'JOINT_FP_BUDGET_CHANGED'
    );
    need(
      p.rules.some((x) => x.enabled),
      'EMPTY_DETECTOR_NOT_AN_IMPROVEMENT'
    );
    need(
      Number.isFinite(p.joint_group_margin) &&
        p.rules.every(
          (x) =>
            typeof x.rule?.id === 'string' &&
            x.rule.id.length > 0 &&
            typeof x.rule.definition === 'string' &&
            x.rule.definition.length > 0 &&
            typeof x.enabled === 'boolean' &&
            Number.isFinite(x.threshold)
        ),
      'CLASSICAL_SEMANTICS_REQUIRED'
    );
    return p;
  };
  const semantics = (p) => {
    const engineered = p.engineered_rules || [],
      ids = new Set(engineered.map((e) => e.id)),
      byID = new Map(p.rules.map((r) => [r.rule.id, r]));
    const formulas = engineered.map((e) => {
      need(
        Array.isArray(e.terms) && e.terms.length >= 2 && e.terms.length <= 4,
        'CLASSICAL_FORMULA_TERMS_REQUIRED'
      );
      const terms = e.terms
        .map((t) => {
          need(
            typeof t.source === 'string' &&
              ['high', 'low', 'band'].includes(t.shape) &&
              Number.isFinite(t.lower) &&
              Number.isFinite(t.upper),
            'CLASSICAL_FORMULA_TERM_INVALID'
          );
          return {
            source: t.source,
            shape: t.shape,
            lower: t.lower,
            upper: t.upper
          };
        })
        .sort((a, b) => canonical(a).localeCompare(canonical(b)));
      const r = byID.get(e.id);
      need(r, 'ENGINEERED_RULE_POLICY_MISSING');
      return { terms, enabled: r.enabled, threshold: r.threshold };
    });
    const unique = [
      ...new Map(formulas.map((f) => [canonical(f), f])).values()
    ].sort((a, b) => canonical(a).localeCompare(canonical(b)));
    return {
      margin: p.joint_group_margin,
      base_rules: p.rules
        .filter((r) => !ids.has(r.rule.id))
        .map((r) => ({
          id: r.rule.id,
          enabled: r.enabled,
          threshold: r.threshold
        }))
        .sort((a, b) => a.id.localeCompare(b.id)),
      engineered_formulas: unique
    };
  };
  let baseline = null;
  if (ledger.cycles.some((r) => r.state !== 'pending')) {
    need(ledger.baseline, 'HEALTHY_B1_REQUIRED');
    baseline = json(ledger.baseline);
    need(
      ((baseline.kind === 'healthy_primary_B1' && baseline.healthy === true) ||
        (baseline.kind === 'completed_primary_B1' &&
          baseline.acquisition_complete === true &&
          baseline.analysis_status === 'INCONCLUSIVE')) &&
        baseline.groups?.length === 71 &&
        SHA.test(baseline.benign_corpus_sha256 || '') &&
        SHA.test(baseline.measurement_contract_sha256 || ''),
      'COMPLETE_71_B1_REQUIRED'
    );
    need(
      new Set(baseline.groups.map((g) => g.group_id)).size === 71 &&
        baseline.groups.every(
          (g) =>
            ['train', 'validation'].includes(g.split) &&
            g.scope === 'primary' &&
            ['benign', 'belnet'].includes(g.class) &&
            !/^q-|^b-test-/.test(g.group_id)
        ),
      'B1_COHORT_NOT_PRIMARY'
    );
    need(
      baseline.groups.filter((g) => g.class === 'benign').length > 0,
      'BENIGN_CONTROLS_REQUIRED'
    );
    const master = json(baseline.collector_freeze),
      index = json(baseline.observer_index);
    need(
      master.stage === 'B1' &&
        master.groups?.length === 71 &&
        index.stage === 'B1' &&
        index.schema === 4 &&
        index.reports?.length === 71,
      'B1_RAW_COHORT_REQUIRED'
    );
    need(
      index.reports.every(
        (r) =>
          baseline.groups.some(
            (g) => g.group_id === r.group_id && g.split === r.split
          ) &&
          Array.isArray(r.coverage_errors) &&
          (r.coverage_errors.length === 0 ||
            baseline.analysis_status === 'INCONCLUSIVE')
      ) &&
        new Set(index.reports.map((r) => r.group_id)).size === 71 &&
        master.groups.every((g) =>
          baseline.groups.some(
            (b) => b.group_id === g.group_id && b.split === g.split
          )
        ),
      'BASELINE_CAPTURE_NOT_HEALTHY'
    );
    time(baseline.completed_at);
    bytes(ledger.protocol);
  }
  function benign(reportRef, policySHA, policyContract) {
    const x = json(reportRef);
    need(
      x.kind === 'joint_benign_FP' &&
        x.aggregation === 'joint_OR_all_rules_windows_flows_reconnects' &&
        x.policy_sha256 === policySHA &&
        x.benign_corpus_sha256 === baseline.benign_corpus_sha256,
      'BENIGN_JOINT_OR_BINDING'
    );
    const raw = json(x.raw_report);
    need(
      raw.stage === 'B1' && raw.policy_sha256 === policySHA,
      'BENIGN_RAW_REPORT_BINDING'
    );
    const contract = 'r4-worst-case-benign-fp-v1';
    need(
      policyContract !== contract || x.analysis_contract === contract,
      'WORST_CASE_FP_CONTRACT_REQUIRED'
    );
    const worstCase = x.analysis_contract === contract;
    need(
      !worstCase || policyContract === contract,
      'WORST_CASE_POLICY_CONTRACT_REQUIRED'
    );
    const expected = baseline.groups.filter((g) => g.class === 'benign');
    const rows = raw.decisions.filter((d) => d.class === 'benign');
    need(
      rows.length === expected.length &&
        new Set(rows.map((r) => r.group_id)).size === rows.length &&
        rows.every(
          (r) =>
            expected.some(
              (g) => g.group_id === r.group_id && g.split === r.split
            ) &&
            typeof r.coverage_complete === 'boolean' &&
            r.scope === 'primary'
        ),
      'BENIGN_DENOMINATOR_CHANGED_OR_UNKNOWN'
    );
    const unknown = rows
      .filter((r) => !r.coverage_complete)
      .map((r) => r.group_id);
    need(
      worstCase || !unknown.length || x.certification === 'INCONCLUSIVE',
      'BENIGN_UNKNOWN_REQUIRES_INCONCLUSIVE'
    );
    let within = true;
    let uncertaintyExceedsBudget = false;
    const splitEvidence = {};
    const detected = (r) => {
      need(
        typeof r.any_detected === 'boolean' || typeof r.detected === 'boolean',
        'BENIGN_VERDICT_REQUIRED'
      );
      need(
        r.any_detected === undefined ||
          r.detected === undefined ||
          r.any_detected === r.detected,
        'BENIGN_VERDICT_CONFLICT'
      );
      return r.any_detected ?? r.detected;
    };
    const equalRatio = (actual, n, denominator) =>
      Number.isFinite(actual) && Math.abs(actual - n / denominator) < 1e-12;
    for (const split of ['train', 'validation']) {
      const m = raw.by_split?.[split];
      need(
        m &&
          m.benign_groups ===
            expected.filter((g) => g.split === split).length &&
          m.benign_groups > 0 &&
          Number.isSafeInteger(m.false_positive_groups) &&
          m.false_positive_groups >= 0 &&
          m.false_positive_groups <= m.benign_groups &&
          Number.isSafeInteger(m.benign_flows) &&
          m.benign_flows > 0 &&
          Number.isSafeInteger(m.direct_rule_hit_false_positive_flows) &&
          m.direct_rule_hit_false_positive_flows >= 0 &&
          m.direct_rule_hit_false_positive_flows <= m.benign_flows,
        'BENIGN_METRICS_REQUIRED'
      );
      const splitRows = rows.filter((r) => r.split === split);
      const flowIDs = new Set(),
        hitIDs = new Set(),
        affectedIDs = new Set(),
        worstGroups = new Set();
      let unbounded = 0;
      const unknownGroups = splitRows.filter((r) => !r.coverage_complete);
      for (const r of splitRows) {
        const inventory = r.primary_flow_inventory || [];
        // Go serializes a nil slice as null on a complete, bounded decision.
        // An incomplete decision still requires its explicit affected inventory.
        const affected = r.coverage_complete === true &&
          r.uncertainty_bounded === true &&
          r.potentially_affected_primary_flows === null
            ? [] : r.potentially_affected_primary_flows;
        if (worstCase) {
          need(
            Array.isArray(inventory) &&
              inventory.every(
                (id) => typeof id === 'string' && id.length > 0
              ) &&
              new Set(inventory).size === inventory.length &&
              typeof r.uncertainty_bounded === 'boolean' &&
              Array.isArray(affected),
            'BOUNDED_FLOW_INVENTORY_REQUIRED'
          );
          need(
            new Set(affected).size ===
              affected.length &&
              affected.every((id) =>
                inventory.includes(id)
              ),
            'AFFECTED_FLOW_OUTSIDE_INVENTORY'
          );
          if (!r.coverage_complete) {
            if (!r.uncertainty_bounded) unbounded++;
            for (const id of affected)
              affectedIDs.add(r.group_id + '/' + id);
          }
        }
        for (const id of inventory) flowIDs.add(r.group_id + '/' + id);
        for (const w of r.windows || []) {
          if (worstCase)
            need(
              inventory.includes(w.flow_id),
              'WINDOW_FLOW_OUTSIDE_PRIMARY_INVENTORY'
            );
          flowIDs.add(r.group_id + '/' + w.flow_id);
          if (w.hits?.length) hitIDs.add(r.group_id + '/' + w.flow_id);
        }
        if (!r.coverage_complete || detected(r)) worstGroups.add(r.group_id);
      }
      need(
        m.false_positive_groups === splitRows.filter(detected).length &&
          m.benign_flows === flowIDs.size &&
          m.direct_rule_hit_false_positive_flows === hitIDs.size,
        'FP_METRICS_DISAGREE_WITH_VERDICTS'
      );
      need(
        equalRatio(m.group_fpr, m.false_positive_groups, m.benign_groups) &&
          equalRatio(
            m.direct_rule_hit_flow_fpr,
            m.direct_rule_hit_false_positive_flows,
            m.benign_flows
          ),
        'FP_RATIO_INCORRECT'
      );
      if (worstCase) {
        const worstFlows = new Set([...hitIDs, ...affectedIDs]);
        need(
          m.worst_case_false_positive_groups === worstGroups.size &&
            equalRatio(
              m.worst_case_group_fpr,
              worstGroups.size,
              m.benign_groups
            ) &&
            m.worst_case_direct_rule_hit_false_positive_flows ===
              worstFlows.size &&
            m.unbounded_benign_inventory_groups === unbounded &&
            m.incomplete_benign_potential_false_positive_groups ===
              unknownGroups.length,
          'WORST_CASE_FP_METRICS_DISAGREE'
        );
        need(
          unbounded
            ? m.worst_case_direct_flow_fpr === null
            : equalRatio(
                m.worst_case_direct_flow_fpr,
                worstFlows.size,
                m.benign_flows
              ),
          'WORST_CASE_FLOW_RATIO_INCORRECT'
        );
        const floorExceeds =
          unbounded > 0 ||
          unknownGroups.length / m.benign_groups > 0.05 ||
          affectedIDs.size / m.benign_flows > 0.05;
        uncertaintyExceedsBudget ||= floorExceeds;
        within &&=
          !unbounded &&
          m.worst_case_group_fpr <= 0.05 &&
          m.worst_case_direct_flow_fpr <= 0.05;
        splitEvidence[split] = {
          observed_FP: m.false_positive_groups,
          unknown: unknownGroups.length,
          worst_case_FP: worstGroups.size,
          worst_case_FPR: m.worst_case_group_fpr,
          worst_case_FP_flows: worstFlows.size,
          worst_case_flow_FPR: m.worst_case_direct_flow_fpr,
          unbounded_inventory_groups: unbounded
        };
      } else {
        within &&=
          unknown.length === 0 &&
          m.group_fpr <= 0.05 &&
          m.direct_rule_hit_flow_fpr <= 0.05;
      }
    }
    if (x.certification === 'INCONCLUSIVE') within = false;
    const certification =
      (!worstCase && unknown.length) ||
      uncertaintyExceedsBudget ||
      x.certification === 'INCONCLUSIVE'
        ? 'INCONCLUSIVE'
        : within
          ? 'CERTIFIED'
          : 'FAILED_BUDGET';
    return {
      within,
      certification,
      unknown_groups: unknown,
      worst_case_benign_fp: worstCase ? splitEvidence : null,
      evaluated_at: x.evaluated_at
    };
  }
  const results = [];
  for (const row of ledger.cycles) {
    if (row.state !== 'complete') continue;
    if (row.cycle === 1)
      need(
        time(row.hypothesis.selected_at) > time(baseline.completed_at),
        'HYPOTHESIS_PRECEDED_HEALTHY_B1'
      );
    const e = json(row.evidence);
    need(
      e.kind === 'measured_classical_transport_pair',
      'NOT_AN_ADAPTIVE_PAIR'
    );
    need(
      e.origin === 'actual_measurement' ||
        (allowSynthetic && e.origin === 'synthetic_fixture'),
      'ACTUAL_MEASUREMENTS_REQUIRED'
    );
    const synthetic = e.origin !== 'actual_measurement';
    const feature = json(e.feature);
    need(
      feature.kind === 'measured_feature' &&
        feature.split === 'train' &&
        feature.feature === row.hypothesis.measured_feature &&
        feature.measurements?.length > 0,
      'MEASURED_TRAIN_FEATURE_REQUIRED'
    );
    bytes(feature.raw_evidence);
    need(
      time(feature.observed_at) <= time(row.hypothesis.selected_at),
      'FEATURE_NOT_YET_OBSERVED'
    );
    const d = json(e.detector_delta);
    need(
      d.kind === 'classical_detector_delta' &&
        ['rule', 'threshold'].includes(d.change_kind) &&
        d.changed_rule_ids?.length > 0,
      'DETECTOR_DELTA_REQUIRED'
    );
    const before = classic(d.before_policy),
      after = classic(d.after_policy);
    need(
      digest(semantics(before)) !== digest(semantics(after)),
      'NO_DETECTOR_SEMANTIC_DELTA'
    );
    need(
      d.changed_rule_ids.every((id) =>
        after.rules.some((r) => r.rule.id === id)
      ),
      'CHANGED_CLASSICAL_RULE_ID_UNKNOWN'
    );
    need(
      before.coverage_semantics_sha256 === after.coverage_semantics_sha256 &&
        before.ordering_semantics_sha256 === after.ordering_semantics_sha256 &&
        SHA.test(after.coverage_semantics_sha256 || '') &&
        SHA.test(after.ordering_semantics_sha256 || ''),
      'CAPTURE_ABI_REPAIR_NOT_A_CYCLE'
    );
    sources(d.source_manifest);
    detectorExecutable(d.program);
    detectorExecutable(d.engine);
    need(
      after.score_engine_sha256 === d.engine.sha256,
      'DETECTOR_ENGINE_BINDING'
    );
    need(
      time(after.policy_frozen_at) > time(row.hypothesis.selected_at),
      'DETECTOR_NOT_AFTER_HYPOTHESIS'
    );
    const initialFP = benign(
      e.benign_initial,
      d.after_policy.sha256,
      after.analysis_contract
    );
    const w = json(e.wrapper_build);
    need(w.kind === 'transport_wrapper_change', 'WRAPPER_CHANGE_REQUIRED');
    const a = sources(w.before.source_manifest),
      b = sources(w.after.source_manifest);
    elf(w.before.elf);
    elf(w.after.elf);
    const settingA = json(w.before.settings),
      settingB = json(w.after.settings);
    need(
      settingA.kind === 'transport_settings' &&
        settingB.kind === 'transport_settings' &&
        !settingA.capture_mode &&
        !settingB.capture_mode,
      'CAPTURE_REPAIR_NOT_TRANSPORT'
    );
    const sourceMap = (s) =>
      s.files
        .map((f) => ({
          logical_path: f.logical_path || path.basename(f.path),
          sha256: f.sha256
        }))
        .sort((x, y) => x.logical_path.localeCompare(y.logical_path));
    const sourceChanged =
      digest(sourceMap(a)) !== digest(sourceMap(b)) &&
      w.before.elf.sha256 !== w.after.elf.sha256;
    need(
      sourceChanged || digest(settingA.settings) !== digest(settingB.settings),
      'NO_WRAPPER_RESPONSE'
    );
    const build = json(w.build_record);
    need(
      build.kind === 'wrapper_build' &&
        build.source_manifest_sha256 === w.after.source_manifest.sha256 &&
        build.elf_sha256 === w.after.elf.sha256,
      'WRAPPER_BUILD_BINDING'
    );
    need(
      time(w.selected_at) > time(initialFP.evaluated_at) &&
        time(build.completed_at) >= time(build.started_at),
      'WRAPPER_SELECTION_PRECEDED_DPI_MEASUREMENT'
    );
    const n = json(e.native_proof);
    need(
      n.kind === 'fresh_native_development' &&
        n.wrapper_elf_sha256 === w.after.elf.sha256 &&
        n.wrapper_source_sha256 === w.after.source_manifest.sha256 &&
        n.wrapper_settings_sha256 === w.after.settings.sha256 &&
        n.measurement_contract_sha256 === baseline.measurement_contract_sha256,
      'NATIVE_CANDIDATE_BINDING'
    );
    need(n.max_native_concurrent === 1, 'ONE_NATIVE_AT_A_TIME');
    need(
      n.groups?.length >= 3 &&
        n.groups.length <= 6 &&
        n.groups.some((g) => g.split === 'train') &&
        n.groups.some((g) => g.split === 'validation') &&
        new Set(n.groups.map((g) => g.group_id)).size === n.groups.length &&
        WORKLOADS.every((k) => n.groups.some((g) => g.family === k)),
      'ALL_THREE_NATIVE_FAMILIES_REQUIRED'
    );
    need(
      time(n.frozen_at) >
        Math.max(time(build.completed_at), time(w.selected_at)),
      'NATIVE_NOT_FROZEN_AFTER_SELECTION_AND_BUILD'
    );
    let latest = 0,
      allMainSuccess = true;
    for (const g of n.groups) {
      need(!groupIDs.has(g.group_id), 'NATIVE_GROUP_REUSED');
      groupIDs.add(g.group_id);
      need(
        ['train', 'validation'].includes(g.split) &&
          g.scope === 'primary' &&
          g.class === 'belnet' &&
          g.experiment_role === 'candidate-development' &&
          !/^q-|^b-test-/.test(g.group_id),
        'NATIVE_TEST_OR_DIAGNOSTIC_FORBIDDEN'
      );
      need(
        g.fresh_identity === true &&
          SHA.test(g.identity_sha256 || '') &&
          !identities.has(g.identity_sha256),
        'NATIVE_IDENTITY_REUSED'
      );
      identities.add(g.identity_sha256);
      need(
        g.capture_complete === true &&
          g.native_process_verified === true &&
          g.native_udp_inputs > 0,
        'FRESH_NATIVE_INPUT_AND_CAPTURE_REQUIRED'
      );
      need(
        time(g.capture_started_at) >= time(n.frozen_at) &&
          time(g.capture_ended_at) - time(g.capture_started_at) >= 80000,
        'NATIVE_PRIMARY80S_REQUIRED'
      );
      latest = Math.max(latest, time(g.capture_ended_at));
      need(g.raw_sources?.length >= 3, 'NATIVE_RAW_PROOF_SOURCES_REQUIRED');
      for (const r of g.raw_sources) bytes(r);
      need(
        g.nonce_results?.length === 5 &&
          new Set(g.nonce_results.map((x) => x.label)).size === 5 &&
          ['initial', 'warmup-0', 'warmup-1', 'warmup-2', 'main'].every((k) =>
            g.nonce_results.some((x) => x.label === k)
          ),
        'NATIVE_NONCE_ATTEMPTS_REQUIRED'
      );
      for (const p of g.nonce_results) {
        need(
          NONCE.test(p.nonce || '') && !nonces.has(p.nonce),
          'NONCE_REUSED_OR_INVALID'
        );
        nonces.add(p.nonce);
        need(
          ['success', 'failed'].includes(p.status),
          'NONCE_OUTCOME_REQUIRED'
        );
        if (p.status === 'success')
          need(
            p.service_nonce === p.nonce &&
              Number.isSafeInteger(p.client_bytes) &&
              Number.isSafeInteger(p.server_bytes) &&
              p.client_bytes === p.server_bytes &&
              p.client_bytes > 0,
            'SERVICE_NONCE_PROOF_MISMATCH'
          );
        else
          need(
            typeof p.error === 'string' && p.error.length > 0,
            'FAILED_NONCE_ERROR_REQUIRED'
          );
      }
      allMainSuccess &&=
        g.nonce_results.find((x) => x.label === 'main').status === 'success';
    }
    const scheduled = [...n.groups].sort(
      (a, b) => time(a.capture_started_at) - time(b.capture_started_at)
    );
    need(
      scheduled.every(
        (g, i) =>
          i === 0 ||
          time(g.capture_started_at) >= time(scheduled[i - 1].capture_ended_at)
      ),
      'NATIVE_DEPLOYMENTS_OVERLAP'
    );
    const attack = json(e.last_attack);
    need(
      attack.kind === 'classical_shadow_retest' &&
        attack.scope === 'development_train_validation' &&
        attack.live_enforcement === false,
      'SHADOW_VERDICT_SCOPE_REQUIRED'
    );
    const finalPolicy = classic(attack.policy);
    need(
      finalPolicy.coverage_semantics_sha256 ===
        after.coverage_semantics_sha256 &&
        finalPolicy.ordering_semantics_sha256 ===
          after.ordering_semantics_sha256,
      'CAPTURE_ABI_REPAIR_NOT_A_CYCLE'
    );
    sources(attack.source_manifest);
    detectorExecutable(attack.program);
    detectorExecutable(attack.engine);
    need(
      finalPolicy.score_engine_sha256 === attack.engine.sha256 &&
        time(finalPolicy.last_development_capture_ended_utc) >= latest &&
        time(finalPolicy.policy_frozen_at) > latest &&
        time(attack.evaluated_at) >= time(finalPolicy.policy_frozen_at),
      'ADAPTIVE_ATTACKER_MUST_ACT_LAST'
    );
    const verdict = json(attack.raw_report);
    need(
      verdict.stage === 'B1' && verdict.policy_sha256 === attack.policy.sha256,
      'RETEST_POLICY_BINDING'
    );
    const v = verdict.decisions.filter((x) =>
      n.groups.some((g) => g.group_id === x.group_id)
    );
    need(
      v.length === n.groups.length &&
        new Set(v.map((x) => x.group_id)).size === v.length &&
        v.every(
          (x) =>
            ['train', 'validation'].includes(x.split) &&
            x.class === 'belnet' &&
            x.scope === 'primary' &&
            x.coverage_complete === true &&
            typeof x.any_detected === 'boolean' &&
            typeof x.abstained === 'boolean'
        ),
      'FRESH_CLASSICAL_VERDICTS_REQUIRED'
    );
    const finalFP = benign(
      e.benign_final,
      attack.policy.sha256,
      finalPolicy.analysis_contract
    );
    const cost = json(e.cost);
    need(
      cost.kind === 'native_cost_measurements' &&
        cost.wrapper_elf_sha256 === w.after.elf.sha256 &&
        cost.groups?.length === n.groups.length &&
        new Set(cost.groups.map((g) => g.group_id)).size === n.groups.length,
      'COST_CANDIDATE_BINDING'
    );
    need(time(cost.measured_at) >= latest, 'COST_PRECEDED_ACTUAL_RUN');
    for (const g of cost.groups) {
      need(
        n.groups.some((x) => x.group_id === g.group_id),
        'COST_GROUP_MISMATCH'
      );
      need(
        g.bytes &&
          ['application', 'outer_wire'].every(
            (k) => Number.isSafeInteger(g.bytes[k]) && g.bytes[k] >= 0
          ),
        'MEASURED_BYTES_REQUIRED'
      );
      const l = g.loss;
      need(
        l?.definition === 'bridge_udp_input_to_forward_write' &&
          [
            'inputs',
            'forwarded',
            'expired',
            'dropped',
            'failed',
            'unknown'
          ].every((k) => Number.isSafeInteger(l[k]) && l[k] >= 0) &&
          l.inputs > 0 &&
          l.inputs ===
            l.forwarded + l.expired + l.dropped + l.failed + l.unknown &&
          l.unknown === 0,
        'MEASURED_LOSS_ACCOUNTING_REQUIRED'
      );
      const lat = g.latency;
      need(
        lat?.clock === 'linux-vm' && lat.definition === 'input_to_write_start',
        'LATENCY_DEFINITION_REQUIRED'
      );
      if (l.forwarded) {
        need(
          lat.status === 'measured' &&
            lat.samples === l.forwarded &&
            [lat.p50_ms, lat.p95_ms, lat.max_ms].every(
              (x) => Number.isFinite(x) && x >= 0
            ) &&
            lat.p50_ms <= lat.p95_ms &&
            lat.p95_ms <= lat.max_ms,
          'MEASURED_LATENCY_REQUIRED'
        );
      } else
        need(
          lat.status === 'not_applicable_all_inputs_dropped' &&
            lat.samples === 0 &&
            lat.p50_ms === null &&
            lat.p95_ms === null &&
            lat.max_ms === null,
          'DROPPED_INPUT_LATENCY_NOT_ZERO'
        );
      for (const r of g.raw_sources || []) bytes(r);
      need(g.raw_sources?.length > 0, 'COST_RAW_SOURCE_REQUIRED');
    }
    if (row.decision.outcome === 'accepted')
      need(
        initialFP.within && finalFP.within && allMainSuccess,
        'FAILED_VARIANT_CANNOT_BE_ACCEPTED'
      );
    need(
      time(row.decision.closed_at) >=
        Math.max(
          time(attack.evaluated_at),
          time(finalFP.evaluated_at),
          time(cost.measured_at)
        ),
      'CYCLE_CLOSED_BEFORE_MEASUREMENTS'
    );
    results.push({
      cycle: row.cycle,
      outcome: row.decision.outcome,
      synthetic,
      benign_initial_within_budget: initialFP.within,
      benign_final_within_budget: finalFP.within,
      benign_initial_status: initialFP.certification,
      benign_final_status: finalFP.certification,
      benign_unknown_groups: [
        ...new Set([...initialFP.unknown_groups, ...finalFP.unknown_groups])
      ],
      benign_initial_worst_case: initialFP.worst_case_benign_fp,
      benign_final_worst_case: finalFP.worst_case_benign_fp,
      fresh_native_groups: n.groups.length,
      shadow_detected_groups: v.filter((x) => x.any_detected).length,
      shadow_abstaining_groups: v.filter((x) => x.abstained).length,
      all_main_nonce_success: allMainSuccess
    });
  }
  const actual = results.filter((r) => !r.synthetic).length;
  return {
    validated_complete_rows: results.length,
    actual_complete_cycles: actual,
    pending: ledger.cycles.filter((r) => r.state === 'pending').length,
    in_progress: ledger.cycles.filter((r) => r.state === 'in_progress').length,
    fifteen_actual_cycles_complete: actual === 15,
    accepted: results.filter((r) => r.outcome === 'accepted').length,
    rejected: results.filter((r) => r.outcome === 'rejected').length,
    results,
    input_sha256: inputSHA
  };
}
function planNativeRound(
  ledger,
  cycle,
  candidate,
  {
    replicas = 2,
    seedFor = () => crypto.randomInt(1, 2 ** 48),
    nonceFor = () => crypto.randomBytes(32).toString('hex')
  } = {}
) {
  preflight(ledger);
  const row = ledger.cycles[cycle - 1];
  need(row?.state === 'in_progress', 'CURRENT_IN_PROGRESS_CYCLE_REQUIRED');
  need([1, 2].includes(replicas), 'THREE_OR_SIX_DEPLOYMENTS_ONLY');
  ref(candidate.source_manifest);
  ref(candidate.elf);
  ref(candidate.build_record);
  const seen = new Set(),
    groups = [];
  for (let replica = 0; replica < replicas; replica++)
    for (let j = 0; j < 3; j++) {
      const family = WORKLOADS[j],
        split =
          replicas === 2
            ? replica
              ? 'validation'
              : 'train'
            : j === 1
              ? 'validation'
              : 'train',
        id = `b-${split}-native-cycle${String(cycle).padStart(2, '0')}-${family}`,
        seed = seedFor(id);
      need(
        Number.isSafeInteger(seed) && seed >= 1 && seed < 2 ** 48,
        'SEED_48BIT'
      );
      const nonces = Array.from({ length: 5 }, () => {
        const n = nonceFor();
        need(
          NONCE.test(n || '') && !seen.has(n),
          'FRESH_UNIQUE_NONCE_REQUIRED'
        );
        seen.add(n);
        return n;
      });
      groups.push({
        group_id: id,
        source_workload_id: `cycle${cycle}-${split}-${family}`,
        split,
        scope: 'primary',
        experiment_role: 'candidate-development',
        class: 'belnet',
        stratum: 'native',
        transport: 'reality',
        family,
        profile: `cycle${cycle}-${family}`,
        client_stack: 'native-belnet+sing-box-utls-chrome',
        workload_mode: 'matched45',
        workload_duration_seconds: 45,
        measured_seconds: 80,
        prefix_grace_seconds: 2,
        startup_seconds: 35,
        workload_start_seconds: 35,
        seed_int: seed,
        seed_hex: seed.toString(16).padStart(16, '0'),
        nonce: nonces[0],
        initial_nonce: nonces[1],
        warmup_nonces: nonces.slice(2),
        fresh_native_identity_required: true,
        target_entries: [1, 2],
        synthetic_application: true
      });
    }
  return {
    schema: 'belnet-adaptive-native-plan/v1',
    cycle,
    experiment_role: 'candidate-development',
    candidate,
    groups,
    stages: {
      B1: {
        order: groups.map((g) => g.group_id),
        batches: groups.map((g) => [g.group_id])
      }
    },
    resource_limits: { max_active_groups: 1, max_active_native: 1 },
    real_traffic_started: false,
    test_rows: 0,
    runner: 'node lab/dpi-g03/runtime-v5/collect.cjs --freeze MASTER',
    integration:
      'lead must clone candidate preparation and freeze exact source/ELF/config before collection'
  };
}
module.exports = {
  createLedger,
  rowDigest,
  validateLedger,
  planNativeRound,
  digest
};

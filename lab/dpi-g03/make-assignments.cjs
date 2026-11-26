'use strict';
// Pure preregistration metadata. This never collects traffic or opens test seeds.
const fs = require('node:fs');
const crypto = require('node:crypto');
const hash = text => crypto.createHash('sha256').update(text).digest('hex');
const ROOT_SEED = 'belnet-g03-20261119-b-v1';
const splits = ['train', 'validation', 'test'];
const nativeFamilies = ['rpc', 'download', 'upload'];
const longFamilies = ['push', 'chat', 'idle'];
const publicCases = [
  ['google', 'https://www.google.com/'],
  ['youtube', 'https://www.youtube.com/watch?v=aqz-KE-bpKQ&autoplay=1&hl=en'],
  ['docs', 'https://www.rfc-editor.org/rfc/rfc8446.html'],
  ['download', 'https://speed.cloudflare.com/__down?bytes=1048576']
];
function seeded(source, split) {
  if (split === 'test') return { seed_hex: null, seed_int: null, sealed_seed_ref: source };
  const hex = hash(ROOT_SEED + '|workload|' + source).slice(0, 12);
  const integer = Number.parseInt(hex, 16) || 1;
  return { seed_hex: integer.toString(16).padStart(16, '0'), seed_int: integer, sealed_seed_ref: null };
}
function nonce(group, split, role) {
  return split === 'test' ? null : hash(ROOT_SEED + '|nonce|' + group + '|' + role);
}
function groupBase(id, source, split) {
  return {
    group_id: id, source_workload_id: source, split, scope: 'primary',
    measured_seconds: 80, prefix_grace_seconds: 2,
    startup_seconds: 35, workload_start_seconds: 35,
    ...seeded(source, split), nonce: nonce(id, split, 'main'),
    initial_nonce: nonce(id, split, 'initial'),
    warmup_nonces: [0, 1, 2].map(i => nonce(id, split, 'warmup-' + i)),
    sealed_nonce_ref: split === 'test' ? id : null
  };
}
function makeAssignments() {
  const groups = [];
  for (const split of splits) {
    let localIndex = 0;
    function ordinary(id, source, family, mode) {
      const index = localIndex++;
      groups.push({
        ...groupBase(id, source, split), class: 'benign', stratum: 'local_ordinary',
        transport: 'ordinary-tls', family, profile: 'ordinary-' + mode + '-' + family,
        client_stack: index % 2 ? 'go-wss' : 'chrome',
        workload_mode: mode, workload_duration_seconds: mode === 'long80' ? 80 : 45,
        workload_start_seconds: mode === 'long80' ? 0 : 35,
        entry_index: 1 + Math.floor(index / 2) % 2,
        application_budget_bytes_per_direction: 4194304,
        synthetic_application: true
      });
    }
    const nNative = split === 'train' ? 2 : 1;
    for (const family of nativeFamilies) {
      for (let i = 1; i <= nNative; i++) {
        const source = 'g03-source-' + split + '-' + family + '-' + i;
        const id = 'b-' + split + '-native-' + family + '-' + i;
        groups.push({
          ...groupBase(id, source, split), class: 'belnet', stratum: 'native',
          transport: 'reality', family, profile: 'native-expiry100-' + family,
          client_stack: 'native-belnet+sing-box-utls-chrome',
          workload_mode: 'matched45', workload_duration_seconds: 45,
          target_entries: [1, 2], max_queue_age_micros: 100000,
          application_budget_bytes_per_direction: 4194304,
          fresh_native_identity_required: true, synthetic_application: true
        });
        for (let replica = 1; replica <= 3; replica++) {
          ordinary('b-' + split + '-matched-' + family + '-' + i + '-r' + replica,
            source, family, 'matched45');
        }
      }
    }
    const nLong = split === 'train' ? 6 : 3;
    for (const family of longFamilies) {
      for (let i = 1; i <= nLong; i++) {
        const id = 'b-' + split + '-long-' + family + '-' + i;
        ordinary(id, 'g03-source-' + split + '-long-' + family + '-' + i, family, 'long80');
      }
    }
    for (const [family, url] of publicCases) {
      const id = 'b-' + split + '-public-' + family;
      groups.push({
        ...groupBase(id, 'g03-source-' + split + '-public-' + family, split),
        class: 'benign', stratum: 'public_browser', transport: 'ordinary-tls',
        client_stack: 'chrome', family, profile: 'public-chrome-' + family,
        url, workload_mode: 'public80', workload_duration_seconds: 80,
        workload_start_seconds: 0, synthetic_application: false,
        fresh_profile_required: true, require_actual_access_evidence: true,
        download_directory: 'run-artifacts-only'
      });
    }
  }
  const ordering = stageGroups => stageGroups.slice().sort((a, b) => {
    const key = g => hash(ROOT_SEED + '|order|' + g.group_id);
    return key(a).localeCompare(key(b));
  });
  function batches(stageGroups) {
    const native = ordering(stageGroups.filter(g => g.class === 'belnet'));
    const negative = ordering(stageGroups.filter(g => g.class === 'benign'));
    const count = Math.ceil(stageGroups.length / 3);
    const nativeBatches = new Set(native.map((_, i) => Math.floor(i * count / native.length)));
    const result = [];
    let nativeIndex = 0;
    for (let i = 0; i < count; i++) {
      const positive = nativeBatches.has(i) ? native.shift() : null;
      const size = Math.min(3, stageGroups.length - result.flat().length);
      const row = Array(size).fill(null);
      if (positive) row[nativeIndex++ % size] = positive;
      const used = new Set(positive ? [positive.source_workload_id] : []);
      for (let slot = 0; slot < size; slot++) {
        if (row[slot]) continue;
        const n = negative.findIndex(g => !used.has(g.source_workload_id));
        if (n < 0) throw Error('Cannot schedule independent source plans in a batch');
        row[slot] = negative.splice(n, 1)[0];
        used.add(row[slot].source_workload_id);
      }
      result.push(row.map(g => g.group_id));
    }
    if (native.length || negative.length) throw Error('Batch scheduler left assignments');
    return result;
  }
  const b1 = batches(groups.filter(g => g.split !== 'test'));
  const b2 = batches(groups.filter(g => g.split === 'test'));
  const plan = {
    schema: 'belnet-g03-assignments/v1', root_seed: ROOT_SEED,
    state: 'preregistered_metadata_not_an_acquisition_authorization',
    primary_seconds: 80, capture_seconds: 82, prefix_grace_seconds: 2,
    measurement_start: 'VM timestamp before client launch and first outer connection',
    window_offsets_seconds: [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 78],
    window_seconds: 2, forced_shadow_interruption: null,
    resource_limits: { max_active_groups: 3, max_active_native_groups: 1, capture_bytes_per_group: 268435456 },
    stages: {
      B1: { splits: ['train', 'validation'], count: 71, batches: b1, order: b1.flat() },
      B2: { splits: ['test'], count: 25, batches: b2, order: b2.flat(),
        requires_candidate_policy_freeze_before_capture: true }
    },
    seeds: {
      train_validation: 'Public deterministic 48-bit source-workload seed; matched variants reuse source seed.',
      test: 'Independent collector CSPRNG, committed privately BEFORE B1 and disclosed only AFTER final policy freeze. Null fields must not be replaced by the public derivation.',
      test_seed_commitment_sha256: null, collector_private_seeds_required_before_B1: true
    },
    notes: [
      'Matched source plans repeat across physical sessions/classes within one split; they are not independent workload samples.',
      'Class/group/split/source IDs are metadata only. No label headers/query fields.',
      'Same-REALITY other payload is excluded from the primary negative cohort.',
      'No source, binary, origin allowlist or private credential hashes are supplied here; a separate actual freeze is required.',
      'All shadow groups use the same no-forced-outage policy. A2 restart proof is separate; active enforcement needs its own finite freeze.'
    ],
    groups
  };
  validate(plan);
  return plan;
}
function validate(plan) {
  if (plan.groups.length !== 96 || new Set(plan.groups.map(g => g.group_id)).size !== 96) throw Error('Group count/uniqueness');
  const sources = new Map(), nonceSet = new Set();
  for (const split of splits) {
    const rows = plan.groups.filter(g => g.split === split);
    const wanted = split === 'train' ? [36, 4, 6] : [18, 4, 3];
    for (const [i, stratum] of ['local_ordinary', 'public_browser', 'native'].entries()) {
      if (rows.filter(g => g.stratum === stratum).length !== wanted[i]) throw Error('Stratum count ' + split);
    }
    const local = rows.filter(g => g.stratum === 'local_ordinary');
    if (local.filter(g => g.client_stack === 'chrome').length !== local.length / 2) throw Error('Stack balance');
  }
  for (const g of plan.groups) {
    if (sources.has(g.source_workload_id) && sources.get(g.source_workload_id) !== g.split) throw Error('Source-workload split leakage');
    sources.set(g.source_workload_id, g.split);
    if (g.split === 'test') {
      if (g.seed_int !== null || g.seed_hex !== null || g.nonce !== null) throw Error('Test seed/nonce must stay sealed');
    } else {
      if (!Number.isSafeInteger(g.seed_int) || g.seed_int < 1 || g.seed_int >= 2 ** 48 ||
          !/^[a-f0-9]{16}$/.test(g.seed_hex)) throw Error('Invalid source seed');
      for (const n of [g.nonce, g.initial_nonce, ...g.warmup_nonces]) {
        if (!/^[a-f0-9]{64}$/.test(n) || nonceSet.has(n)) throw Error('Nonce collision');
        nonceSet.add(n);
      }
    }
    if (g.scope === 'primary' && g.class === 'benign' && g.transport === 'reality') throw Error('Primary negative cannot be REALITY');
  }
  for (const [stage, s] of Object.entries(plan.stages)) {
    if (s.order.length !== s.count || new Set(s.order).size !== s.count ||
        JSON.stringify(s.order) !== JSON.stringify(s.batches.flat())) throw Error('Stage order mismatch');
    for (const batch of s.batches) {
      const rows = batch.map(id => plan.groups.find(g => g.group_id === id));
      if (rows.length > 3 || rows.filter(g => g.class === 'belnet').length > 1 ||
          new Set(rows.map(g => g.source_workload_id)).size !== rows.length) throw Error('Unbalanced/source-overlapping batch');
      if (rows.some(g => stage === 'B1' ? g.split === 'test' : g.split !== 'test')) throw Error('Stage split leakage');
    }
  }
}
if (require.main === module) {
  const out = process.argv[2];
  if (!out) { console.error('Use NEW_ASSIGNMENTS_FILE'); process.exitCode = 2; }
  else fs.writeFileSync(out, JSON.stringify(makeAssignments(), null, 2) + '\n', { flag: 'wx', mode: 0o644 });
}
module.exports = { makeAssignments, validate };

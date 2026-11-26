'use strict';
// Converts already audited native runs to ledger evidence. No fit or networking.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { guardRound } = require('./review-round.cjs');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const need = (value, code) => { if (!value) throw Error(code); };
const count = n => Number.isSafeInteger(n) && n >= 0;

function verifySource(source, expected, read) {
  need(source.kind === 'source_manifest' && Array.isArray(source.files) && source.files.length > 0 &&
    expected && Object.keys(expected).length === source.files.length, 'wrapper_source_census_mismatch');
  const names = source.files.map(f => f.logical_path);
  need(names.every(n => typeof n === 'string' && n.length > 0) && new Set(names).size === names.length &&
    names.every(n => expected[n] === source.files.find(f => f.logical_path === n).sha256), 'wrapper_source_provenance_mismatch');
  for (const ref of source.files) read(ref);
}

function operation(o) {
  need(o.attempt_present && /^[a-f0-9]{64}$/.test(o.expected?.nonce || ''), 'attempt_missing');
  const keys = ['sent_messages_vs_up_messages', 'received_messages_vs_down_messages',
    'sent_bytes_vs_up_bytes', 'received_bytes_vs_down_bytes'];
  const exact = Object.keys(o.counts || {}).length === keys.length && keys.every(k => {
    const p = o.counts[k];
    return p && count(p.client) && count(p.server) && p.equal === true && p.client === p.server;
  });
  const up = o.counts?.sent_bytes_vs_up_bytes;
  const down = o.counts?.received_bytes_vs_down_bytes;
  const success = o.unique_nonce_count_and_metadata_proof === true &&
    o.strict_both_endpoints_duration_complete === true && o.client_exit_code === 0 &&
    o.service_nonce_matches === 1 && !o.expected_nonce_reused && exact;
  need(!success || (up.client + down.client > 0 && Number.isSafeInteger(up.client + down.client)), 'empty_success');
  const reasons = [];
  if (o.client_error) reasons.push(o.client_error);
  if (o.client_exit_code !== 0) reasons.push('client_exit_not_zero');
  if (!exact) reasons.push('client_server_counts_not_exact');
  if (!o.unique_nonce_count_and_metadata_proof) reasons.push('nonce_metadata_proof_incomplete');
  if (!o.strict_both_endpoints_duration_complete) reasons.push('both_endpoint_duration_proof_incomplete');
  return {
    label: o.label, nonce: o.expected.nonce, status: success ? 'success' : 'failed',
    service_nonce: success ? o.expected.nonce : null,
    client_bytes: count(up?.client) && count(down?.client) ? up.client + down.client : null,
    server_bytes: count(up?.server) && count(down?.server) ? up.server + down.server : null,
    error: success ? null : reasons.join('; ') || 'native_proof_incomplete',
    direction_counts: o.counts, times: o.times,
    client_exit_code: o.client_exit_code,
    nonce_count_metadata_proof: o.unique_nonce_count_and_metadata_proof,
    both_endpoint_duration_complete: o.strict_both_endpoints_duration_complete
  };
}

function build(manifest) {
  need(manifest.schema === 'native-ledger-inputs/v1', 'input_schema');
  const inputs = {};
  function read(ref) {
    need(typeof ref?.path === 'string' && /^[a-f0-9]{64}$/.test(ref.sha256 || ''), 'pinned_ref_required');
    const filename = path.resolve(ref.path);
    need(!/vault|sealed[-_]|private[-_]test|(?:^|[\\/])b-test-|(?:^|[\\/])b2(?:[\\/]|$)/i.test(filename), 'test_artifact_forbidden');
    const b = fs.readFileSync(filename);
    need(sha(b) === ref.sha256, 'input_hash_mismatch:' + filename);
    inputs[filename] = ref.sha256;
    return b;
  }
  const json = ref => JSON.parse(read(ref));
  const frozen = json(manifest.freeze);
  guardRound(frozen); // Reject non-development stages before any other input.
  const raw = json(manifest.acquisition);
  need(raw.schema === 'g03-root-adaptive-round-acquisition/v1' &&
    raw.collector_freeze?.sha256 === manifest.freeze.sha256 &&
    raw.adaptive_round === frozen.adaptive_round && raw.raw_acquisition_qualified === true &&
    raw.analysis_input_allowed === true && raw.terminal_completed === true &&
    raw.restoration_complete === true && !raw.errors.length && !raw.missing_groups.length,
  'raw_round_not_released');
  const native = json(manifest.native_review);
  const cost = json(manifest.cost);
  const baseline = json(manifest.baseline);
  const wrapperSource = json(manifest.wrapper_source);
  need(json(manifest.wrapper_settings).kind === 'transport_settings', 'settings_required');
  const prep = json(frozen.prepared);
  verifySource(wrapperSource, prep.adapter_source_provenance?.source_sha256, read);
  read(prep.adapter);
  need(raw.candidate_elf_sha256 === prep.adapter.sha256 && cost.wrapper_elf_sha256 === prep.adapter.sha256, 'elf_binding');
  need(native.schema === 'g03-native-adaptive-round-review/v1' && native.freeze_sha256 === manifest.freeze.sha256 &&
    native.adaptive_round === frozen.adaptive_round && native.reviewed_native_groups === frozen.groups.length &&
    !native.missing_groups.length && !native.service_parse_errors.length, 'native_review_binding');
  need(cost.kind === 'native_cost_measurements' && cost.status === 'measured' &&
    cost.producer_semantics_verified === true && cost.groups.length === frozen.groups.length, 'measured_cost_required');
  // These are explicit audited paths only, not a filesystem scan or test read.
  for (const [filename, hash] of Object.entries(native.input_sha256)) read({ path: filename, sha256: hash });
  for (const g of cost.groups) for (const ref of g.raw_sources) read(ref);
  for (const ref of Object.values(cost.producer_source_refs || {})) read(ref);
  const seenIdentities = new Set();
  for (const ref of manifest.prior_identity_refs || []) seenIdentities.add(sha(read(ref)));
  const seenNonces = new Set();
  const run = path.resolve(manifest.run_directory);
  const groups = frozen.groups.map(g => {
    const dir = path.join(run, g.group_id);
    const filename = path.join(dir, 'result.json');
    const recordRef = { path: filename, sha256: native.input_sha256[filename] };
    const record = json(recordRef);
    need(isDeepStrictEqual(record.group, g), 'assignment_mismatch');
    const proof = native.groups.find(x => x.group_id === g.group_id);
    const c = cost.groups.find(x => x.group_id === g.group_id);
    const a = raw.groups.find(x => x.group_id === g.group_id);
    need(proof && c && a?.acquisition_qualified === true, 'complete_native_acquisition_required');
    need(proof.processes.continuous_at_samples && proof.processes.adapter_pid_files_match &&
      proof.processes.samples.length > 0 && proof.processes.samples.every(s => s.command_ok && s.native_executable === '/usr/local/bin/belnet'),
    'native_process_not_verified');
    const identityPath = path.join(dir, 'data/service.private');
    const identity = fs.readFileSync(identityPath); // Hash only; never emit key bytes.
    need(identity.length > 0 && !seenIdentities.has(sha(identity)), 'empty_or_reused_identity');
    const identityRef = { path: identityPath, sha256: sha(identity) };
    read(identityRef); seenIdentities.add(identityRef.sha256);
    const attempts = proof.operations.map(operation);
    need(attempts.length === 5 && new Set(attempts.map(x => x.label)).size === 5, 'five_attempts_required');
    for (const p of attempts) {
      need(!seenNonces.has(p.nonce), 'reused_nonce'); seenNonces.add(p.nonce);
    }
    need(g.fresh_native_identity_required === true && c.loss.inputs > 0 && c.loss.unknown === 0, 'native_inputs_required');
    const refs = [recordRef, identityRef, manifest.freeze, manifest.native_review, manifest.acquisition,
      ...Object.entries(native.input_sha256).filter(([p]) => p.startsWith(dir + path.sep) || p === path.join(run, 'bb-g03-service.log')).map(([p,h]) => ({path:p,sha256:h}))];
    return {
      group_id: g.group_id, family: g.family, split: g.split, scope: g.scope,
      class: g.class, experiment_role: g.experiment_role,
      fresh_identity: true, identity_sha256: identityRef.sha256,
      identity_scope: 'Generated endpoint service.private hash in the fresh per-deployment data directory; not a DPI feature or a router identity claim',
      capture_complete: true, native_process_verified: true, native_udp_inputs: c.loss.inputs,
      capture_started_at: record.capture_start.utc, capture_ended_at: record.capture_end.utc,
      primary_started_at: record.measurement_start.utc, primary_seconds: 80,
      nonce_results: attempts,
      raw_sources: [...new Map(refs.map(r => [r.path,r])).values()],
      process_scope: proof.processes.scope,
      process_VM_bounds_complete_and_valid: proof.processes.VM_bounds_complete_and_valid,
      sampled_stream_continuity: proof.streams.continuous_at_samples,
      native_log_census: proof.native_log_census,
      raw_UDP_leak: proof.raw_UDP_leak
    };
  });
  return {
    kind: 'fresh_native_development', adaptive_round: frozen.adaptive_round,
    wrapper_elf_sha256: prep.adapter.sha256, wrapper_source_sha256: manifest.wrapper_source.sha256,
    wrapper_settings_sha256: manifest.wrapper_settings.sha256,
    measurement_contract_sha256: baseline.measurement_contract_sha256,
    max_native_concurrent: frozen.max_active_groups, frozen_at: frozen.frozen_at,
    groups, input_sha256: inputs, private_test_values_read: false,
    cost: manifest.cost,
    limits: ['Success requires exact counts and completed duration at both endpoints; all five attempts retained',
      'Process verification is sampled; invalid VM bounds and incomplete stream samples remain explicit',
      'Cost is client UDP input to TCP write-start, not end-to-end delivery or reverse-path cost',
      'Fresh endpoint key hashes are uniqueness evidence; no claim about arbitrary compromise or live DPI bypass']
  };
}

if (require.main === module) {
  const [input, output] = process.argv.slice(2);
  if (!output) throw Error('usage: node native-cost-evidence.cjs INPUT_MANIFEST NEW_NATIVE_DTO');
  const result = build(JSON.parse(fs.readFileSync(input)));
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', {flag:'wx',mode:0o600});
  console.log(JSON.stringify({groups:result.groups.length, successes:result.groups.flatMap(g=>g.nonce_results).filter(p=>p.status==='success').length, cost:result.cost}));
}
module.exports = { operation, build, verifySource };

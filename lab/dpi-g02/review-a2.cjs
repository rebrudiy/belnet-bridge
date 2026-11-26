'use strict';

// Passive audit only. It never launches traffic, fits DPI or changes a run.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { processIdentity, serviceProofs, framedTuples, outerCaptureAccounting } =
  require('../dpi-g01/review-stage-a.cjs');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const sum = (rows, field) => rows.reduce((n, r) => n + (Number(r[field]) || 0), 0);
const max = (rows, field) => Math.max(0, ...rows.map(r => Number(r[field]) || 0));

function freshVMProofs(record) {
  const end = record.interruption?.interruption_ended_unix_micros;
  if (!Number.isSafeInteger(end)) return [];
  return (record.proofs || []).filter(p =>
    p.ok === true && Number.isSafeInteger(p.started_unix_micros) &&
    Number.isSafeInteger(p.finished_unix_micros) &&
    p.started_unix_micros >= end && p.finished_unix_micros >= p.started_unix_micros
  ).sort((a, b) => a.finished_unix_micros - b.finished_unix_micros);
}

function queueAudit(data, limit) {
  const errors = [], missing = [];
  if (!data || data.metadata_truncated !== false) {
    return { errors, missing: ['complete client metadata'], freshness_verified: null };
  }
  const arrays = ['connections', 'packet_events', 'expired_events', 'udp_inputs'];
  if (arrays.some(k => !Array.isArray(data[k]))) {
    return { errors, missing: ['all client event arrays'], freshness_verified: null };
  }
  const connections = data.connections;
  if (!connections.length) missing.push('client connection state');
  for (const c of connections) {
    if (c.max_queue_age_micros !== limit) errors.push('recorded policy differs from frozen assignment');
  }
  const up = data.packet_events.filter(e => e.direction > 0);
  const expired = data.expired_events;
  const accepted = data.udp_inputs.filter(e => e.accepted === true);
  const overflow = data.udp_inputs.filter(e => e.accepted === false);
  const failed = sum(connections, 'failed_write_datagrams');
  if (sum(connections, 'up_datagrams') !== up.length ||
      sum(connections, 'up_bytes') !== sum(up, 'bytes')) {
    errors.push('successful frame counters disagree with packet events');
  }
  if (sum(connections, 'expired_datagrams') !== expired.length ||
      sum(connections, 'expired_bytes') !== sum(expired, 'bytes')) {
    errors.push('expired counters disagree with expiration events');
  }
  if (limit === 0 && expired.length) errors.push('retain mode expired input');
  if (limit > 0) {
    if (up.some(e => !Number.isSafeInteger(e.input_unix_micros) ||
      !Number.isSafeInteger(e.queue_wait_micros) || e.queue_wait_micros < 0 ||
      e.queue_wait_micros > limit)) errors.push('successful local write violates queue freshness limit');
    if (expired.some(e => e.reason === 'max_forward_age' &&
      (e.age_micros <= limit || e.max_queue_age_micros !== limit))) {
      errors.push('expiration did not preserve actual age/limit');
    }
  }
  const observedMax = max(connections, 'max_all_input_age_micros');
  const expiredMax = max(expired, 'age_micros');
  const forwardedMax = max(up, 'queue_wait_micros');
  if (observedMax < Math.max(expiredMax, forwardedMax)) errors.push('all-input age hid consumed stale input');
  const pending = accepted.length - up.length - expired.length - failed;
  if (pending < 0) errors.push('consumed packets exceed accepted inputs');
  return {
    errors, missing, policy_micros: limit,
    freshness_verified: limit > 0 ? errors.length === 0 && missing.length === 0 : null,
    input_datagrams: data.udp_inputs.length, input_bytes: sum(data.udp_inputs, 'bytes'),
    accepted_datagrams: accepted.length, queue_overflow_datagrams: overflow.length,
    locally_written_datagrams: up.length, locally_written_bytes: sum(up, 'bytes'),
    expired_datagrams: expired.length, expired_bytes: sum(expired, 'bytes'),
    expiration_exercised: limit > 0 && expired.some(e => e.reason === 'max_forward_age'),
    missing_timestamp_expirations: expired.filter(e => e.reason === 'missing_input_timestamp').length,
    failed_write_delivery_unknown: failed, accepted_pending_or_unobserved: pending,
    max_successful_local_queue_age_micros: forwardedMax,
    max_expired_age_micros: expiredMax, max_all_consumed_input_age_micros: observedMax,
    max_blocked_local_write_micros: max(up, 'blocked_write_micros'),
    scope: 'Lifetime client inputs and local write attempts, including warmup/outage. Local writes do not prove remote delivery; pending inputs are not silently classified as lost.'
  };
}

function groupAudit(record, assignment, plan, snapshots, services, nonces) {
  const errors = [], missing = [];
  if (JSON.stringify(record.group) !== JSON.stringify(assignment)) errors.push('group assignment mismatch');
  if (!record.completed_schedule) missing.push('completed schedule');
  if (record.warmup?.length !== 3 || record.proofs?.length !== plan.phase_fetch_start_ms.length) missing.push('all scheduled attempts');
  const baseline = record.warmup?.at(-1)?.ok === true;
  if (record.own_warmup_conclusive !== baseline) errors.push('baseline flag disagrees with last warmup');
  const start = record.phase_started_unix_micros, end = record.phase_finished_unix_micros;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
      end - start !== plan.phase_ms * 1000) errors.push('VM phase window mismatch');
  if (!(record.phase_end_clock?.unix_micros >= end)) missing.push('observation through phase end');
  const restored = record.interruption?.interruption_ended_unix_micros;
  if (!Number.isSafeInteger(restored) || restored !== record.interruption?.vm_after_start?.unix_micros) {
    errors.push('VM restoration edge missing/inconsistent');
  }
  let joined = 0;
  for (const p of [...(record.warmup || []), ...(record.proofs || [])]) {
    if (!/^[a-f0-9]{64}$/.test(p.nonce || '')) { missing.push('attempt nonce'); continue; }
    if (nonces.has(p.nonce)) errors.push('reused nonce');
    nonces.add(p.nonce);
    if (!p.ok) continue;
    if (p.status !== 200 || p.body_bytes !== p.requested_bytes) errors.push('invalid successful response size/status');
    const rows = services.get(p.nonce) || [];
    if (rows.length !== 1 || rows[0].bytes !== p.requested_bytes) {
      missing.push('unique service proof for ' + p.nonce); continue;
    }
    if (!(rows[0].at_unix_micros >= p.started_unix_micros &&
          rows[0].at_unix_micros <= p.finished_unix_micros)) {
      errors.push('service timestamp outside VM request interval');
    } else joined++;
  }
  const indices = (record.proofs || []).map(p => p.index);
  if (new Set(indices).size !== indices.length ||
      indices.some(i => !Number.isInteger(i) || i < 0 || i >= plan.phase_fetch_start_ms.length)) {
    errors.push('duplicate/invalid phase index');
  }
  for (const p of record.proofs || []) {
    if (p.requested_bytes !== plan.proof_sizes[p.index % plan.proof_sizes.length]) errors.push('body size differs from plan');
  }
  const first = freshVMProofs(record)[0];
  const delay = first ? first.finished_unix_micros - restored : null;
  if (record.recovery_micros !== delay) errors.push('runtime recovery differs from fresh VM proof');
  const before = processIdentity(record.pid_before), after = processIdentity(record.pid_after);
  const processes = before && after ? JSON.stringify(before) === JSON.stringify(after) : null;
  if (processes === null) missing.push('process identity');
  const tuples = framedTuples(snapshots);
  const final = snapshots.find(s => s.label === 'phase-end');
  const policy = assignment.max_queue_age === '100ms' ? 100000 : assignment.max_queue_age === '0' ? 0 : NaN;
  if (!Number.isFinite(policy)) errors.push('unknown frozen freshness policy');
  const queues = [0, 1].map(i => {
    const client = final?.clients?.[i];
    const q = queueAudit(client?.ok ? client.data : null, policy);
    for (const e of q.errors) errors.push('entry' + (i + 1) + ': ' + e);
    for (const m of q.missing) missing.push('entry' + (i + 1) + ': ' + m);
    return { entry: i + 1, ...q };
  });
  const accounting = outerCaptureAccounting(record.captures || []);
  const noReportedCaptureFailure = record.captures?.length === 3 && record.captures.every(c =>
    c.incomplete === false && c.capped === false && c.dropped_by_kernel === 0 && c.bytes > 0);
  if (accounting.verified === null) missing.push('complete outer capture accounting');
  return {
    id: assignment.id, variant: assignment.variant, errors, missing: [...new Set(missing)],
    gates: {
      baseline_healthy: baseline, native_and_adapters_unchanged: processes,
      udp_tuple_retained: tuples.verified, fresh_post_restart: Boolean(first),
      observed_fresh_response_within_10s: baseline && delay !== null && delay <= plan.recovery_gate_ms * 1000,
      successful_nonces_joined: joined === [...(record.warmup || []), ...(record.proofs || [])].filter(p => p.ok).length,
      no_reported_capture_failure: Boolean(noReportedCaptureFailure),
      outer_capture_accounting: accounting.verified,
      expiry_local_forwarding_contract: policy > 0 ? queues.every(q => q.freshness_verified === true) : null
    },
    warmup_success: record.warmup?.filter(p => p.ok).length || 0,
    phase_success: record.proofs?.filter(p => p.ok).length || 0,
    service_nonce_joins: joined, fresh_response_delay_micros: delay,
    first_fresh_proof_index: first?.index ?? null, queues, tuples,
    capture_accounting: accounting, runtime_errors: record.errors || [],
    scope: 'Fresh sampled response delay, not the exact instant availability returned. Expired input is lost locally, not evidence that all datagrams arrived within100ms.'
  };
}

function auditRun(directory) {
  const inputs = {};
  function read(file) {
    const p = path.resolve(directory, file), bytes = fs.readFileSync(p);
    inputs[p] = sha(bytes);
    return bytes.toString('utf8');
  }
  const started = JSON.parse(read('run-start.json')), status = JSON.parse(read('status.json'));
  const trials = JSON.parse(read('trials.json')), plan = started.plan;
  if (!Array.isArray(plan?.groups) || plan.groups.length !== 4 ||
      plan.groups.map(g => g.max_queue_age).join(',') !== '0,100ms,100ms,0' ||
      plan.groups.some(g => !/^[a-z0-9-]{1,64}$/.test(g.id))) throw Error('Frozen ABBA plan mismatch');
  const services = serviceProofs(read('service.log')), nonces = new Set();
  const errors = [], missing = [];
  if (status.status !== 'complete_engineering_checkpoint' || status.groups !== 4 || trials.length !== 4) missing.push('complete finite A2 checkpoint');
  if (status.dpi_collection_authorized !== false) errors.push('A2 must not authorize DPI collection');
  const groups = plan.groups.map(g => {
    const matches = trials.filter(r => r.group?.id === g.id);
    if (matches.length !== 1) throw Error('Missing or duplicate group: ' + g.id);
    const snapshots = read(g.id + '/snapshots.jsonl').trim().split('\n').filter(Boolean).map(JSON.parse);
    return groupAudit(matches[0], g, plan, snapshots, services, nonces);
  });
  const allErrors = [...errors, ...groups.flatMap(g => g.errors.map(e => g.id + ': ' + e))];
  const allMissing = [...missing, ...groups.flatMap(g => g.missing.map(e => g.id + ': ' + e))];
  return {
    schema: 'belnet-g02-independent-a2-review/v1', generated_at_utc: new Date().toISOString(),
    auditor_sha256: sha(fs.readFileSync(__filename)),
    shared_helper_sha256: sha(fs.readFileSync(require.resolve('../dpi-g01/review-stage-a.cjs'))),
    errors: allErrors, missing: allMissing, groups, input_sha256: inputs,
    data_integrity_verified: allErrors.length === 0 && allMissing.length === 0,
    limits: ['No packet collection, Docker mutation or DPI fitting.',
      'Wire cost/rawUDP and independent TCP parsing are separate audits.',
      'A successful local TCP write is not remote UDP acknowledgement.',
      'Queue conservation describes consumed/remaining local inputs; failed-write delivery is unknown.',
      'Only four development deployments on one private TESTNET; no mainnet/ISP/statistical anonymity claim.']
  };
}

if (require.main === module) {
  try {
    const argv = process.argv.slice(2), args = {};
    for (let i = 0; i < argv.length; i += 2) {
      if (!['--run', '--out'].includes(argv[i]) || argv[i + 1] === undefined) throw Error('Use --run DIR [--out NEWFILE]');
      args[argv[i].slice(2)] = argv[i + 1];
    }
    if (!args.run) throw Error('Use --run DIR [--out NEWFILE]');
    const report = auditRun(path.resolve(args.run)), output = JSON.stringify(report, null, 2) + '\n';
    if (args.out) fs.writeFileSync(args.out, output, { flag: 'wx', mode: 0o600 });
    else process.stdout.write(output);
    if (report.errors.length || report.groups.some(g => g.errors.length)) process.exitCode = 1;
    else if (report.missing.length || report.groups.some(g => g.missing.length)) process.exitCode = 2;
  } catch (e) { console.error(e.message); process.exitCode = 2; }
}

module.exports = { freshVMProofs, queueAudit, groupAudit, auditRun };

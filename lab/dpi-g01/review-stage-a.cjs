'use strict';

// Independent read-only audit. No Docker calls, fitting, collection or gate changes.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const epoch = value => typeof value === 'string' ? Date.parse(value) : NaN;

function processIdentity(text) {
  if (typeof text !== 'string') return null;
  const lines = text.trim().split('\n');
  if (lines.length !== 3 || !/^\d+$/.test(lines[0]) || !/^\d+$/.test(lines[1])) return null;
  const native = lines[2].match(/^(\d+) \((.*)\) (.*)$/);
  if (!native) return null;
  const fields = native[3].trim().split(/\s+/); // field3=state, field22=starttime
  if (!/^\d+$/.test(fields[19] || '')) return null;
  return { adapters: lines.slice(0, 2), native_pid: native[1], native_start_ticks: fields[19] };
}

function serviceProofs(text) {
  const matches = new Map();
  for (const line of text.split('\n')) {
    let proof;
    try {
      const row = JSON.parse(line);
      if (/^[a-f0-9]{64}$/.test(row.nonce || '') && Number.isInteger(row.bytes)) {
        proof = { nonce: row.nonce, bytes: row.bytes, at_unix_micros: row.at_unix_micros, utc: row.utc };
      }
    } catch { /* Legacy service evidence uses a text log. */ }
    if (!proof) {
      const m = line.match(/proof nonce=([a-f0-9]{64}) bytes=(\d+)(?:\s|$)/);
      if (m) proof = { nonce: m[1], bytes: Number(m[2]) };
    }
    if (!proof) continue;
    const rows = matches.get(proof.nonce) || [];
    rows.push(proof);
    matches.set(proof.nonce, rows);
  }
  return matches;
}

function freshProofs(record, vmAheadUpperMS = 0) {
  const ended = epoch(record.interruption && record.interruption.interruption_ended);
  if (!Number.isFinite(ended)) return [];
  return (record.proofs || []).filter(p =>
    p.ok === true && Number.isFinite(epoch(p.started)) &&
    epoch(p.started) - vmAheadUpperMS >= ended && epoch(p.finished) >= epoch(p.started)
  ).sort((a, b) => epoch(a.finished) - epoch(b.finished));
}

function framedTuples(snapshots) {
  const before = snapshots.find(s => s.label === 'pre-reset');
  const after = snapshots.find(s => s.label === 'phase-end');
  if (!before || !after) return { verified: false, reason: 'missing boundary snapshots' };
  const entries = [];
  for (let i = 0; i < 2; i++) {
    const a = before.clients && before.clients[i];
    const b = after.clients && after.clients[i];
    const x = before.servers && before.servers[i];
    const y = after.servers && after.servers[i];
    const states = [a, b, x, y];
    if (states.some(s => !s || !s.ok || !s.data || s.data.metadata_truncated)) {
      entries.push({ entry: i + 1, verified: false, reason: 'missing/truncated metadata' });
      continue;
    }
    const live = s => (s.data.connections || []).filter(c => c.connected && c.session_hash);
    const clientBefore = live(a), clientAfter = live(b);
    const expected = [...new Set(clientBefore.map(c => c.session_hash))];
    const pairs = expected.map(id => {
      const old = live(x).filter(c => c.session_hash === id);
      const next = live(y).filter(c => c.session_hash === id);
      return {
        session_hash: id,
        before: old.map(c => c.udp_tuple),
        after: next.map(c => c.udp_tuple),
        verified: old.length === 1 && next.length === 1 &&
          old[0].udp_tuple === next[0].udp_tuple &&
          clientAfter.some(c => c.session_hash === id)
      };
    });
    entries.push({ entry: i + 1, verified: pairs.length > 0 && pairs.every(p => p.verified), pairs });
  }
  return { verified: entries.length === 2 && entries.every(e => e.verified), entries };
}

function outerCaptureAccounting(captures) {
  const outer = captures.filter(c => /-capture$/.test(c.name || ''));
  if (outer.length !== 1) return { verified: null, reason: 'one outer capture report required' };
  const c = outer[0];
  if (!Number.isSafeInteger(c.captured) || !Number.isSafeInteger(c.received_by_filter)) {
    return { verified: null, reason: 'outer capture counters unavailable' };
  }
  return {
    verified: c.captured === c.received_by_filter ? true : null,
    captured: c.captured, received_by_filter: c.received_by_filter,
    reason: c.captured === c.received_by_filter ? 'reported counters agree' :
      'filter/captured mismatch; zero kernel drops alone does not prove full accounting'
  };
}

function auditGroup(record, group, plan, snapshots, services, seenNonces, clock = null) {
  const errors = [], missing = [];
  if (!record.group || record.group.id !== group.id || record.group.kind !== group.kind ||
      record.group.split !== group.split) errors.push('assignment mismatch');
  if ((record.warmup || []).length !== plan.warmup_start_ms.length) missing.push('complete warmup schedule');
  if ((record.proofs || []).length !== plan.phase_fetch_start_ms.length) missing.push('complete proof schedule');
  const indices = (record.proofs || []).map(p => p.index);
  if (new Set(indices).size !== indices.length ||
      indices.some(i => !Number.isInteger(i) || i < 0 || i >= plan.phase_fetch_start_ms.length)) {
    errors.push('duplicate/invalid phase proof index');
  }
  for (const p of record.proofs || []) {
    if (p.requested_bytes !== plan.proof_sizes[p.index % plan.proof_sizes.length]) {
      errors.push('phase body size differs from frozen schedule');
    }
  }
  const baseline = (record.warmup || []).at(-1)?.ok === true;
  const baselineFlag = record.own_warmup_conclusive ?? record.app_baseline_conclusive;
  if (typeof baselineFlag !== 'boolean') missing.push('reported per-deployment baseline flag');
  else if (baselineFlag !== baseline) errors.push('baseline flag disagrees with last warmup');
  const successes = [...(record.warmup || []), ...(record.proofs || [])].filter(p => p.ok === true);
  let joined = 0;
  for (const p of [...(record.warmup || []), ...(record.proofs || [])]) {
    if (!/^[a-f0-9]{64}$/.test(p.nonce || '')) { missing.push('nonce missing'); continue; }
    if (seenNonces.has(p.nonce)) errors.push('nonce reused across attempts');
    seenNonces.add(p.nonce);
    if (!p.ok) continue;
    if (p.body_bytes !== p.requested_bytes || p.status !== 200) errors.push('successful proof has wrong size/status');
    const rows = services.get(p.nonce) || [];
    if (rows.length === 1 && rows[0].bytes === p.requested_bytes) {
      joined++;
      const at = rows[0].at_unix_micros;
      if (!Number.isSafeInteger(at)) missing.push('service-side UTC timestamp for ' + p.nonce);
      else if (!(at >= epoch(p.started) * 1000 && at < (epoch(p.finished) + 1) * 1000)) {
        errors.push('service nonce lies outside client request time: ' + p.nonce);
      }
    } else missing.push('unique service-side nonce/size proof for ' + p.nonce);
  }
  const rawFresh = freshProofs(record);
  const fresh = clock ? freshProofs(record, clock.upper) : [];
  const ended = epoch(record.interruption?.interruption_ended);
  const rawRecovery = rawFresh.length ? epoch(rawFresh[0].finished) - ended : null;
  const recovery = fresh.length ? epoch(fresh[0].finished) - clock.lower - ended : null;
  const recoveryLower = fresh.length ? epoch(fresh[0].finished) - clock.upper - ended : null;
  if (!clock) missing.push('host/VM clock offset evidence for recovery timing');
  const before = processIdentity(record.pid_before), after = processIdentity(record.pid_after);
  if (!before || !after) missing.push('native and adapter process identity');
  const unchanged = before && after ? JSON.stringify(before) === JSON.stringify(after) : null;
  const phase = epoch(record.phase_finished) - epoch(record.phase_started);
  const captures = record.captures || [];
  if (captures.length !== 3) missing.push('all three capture reports');
  const captureMetadataClean = captures.length === 3 && captures.every(c =>
    c.incomplete === false && c.capped === false && c.dropped_by_kernel === 0 && c.bytes > 0
  );
  const accounting = outerCaptureAccounting(captures);
  if (accounting.verified === null) missing.push('full outer capture accounting: ' + accounting.reason);
  const tuples = group.kind === 'framed' ? framedTuples(snapshots) :
    { verified: null, reason: 'v2 requires independent entry UDP log/tuple analysis' };
  const gates = {
    completed_schedule: record.completed_schedule === true,
    last_warmup_success: baseline,
    phase_duration: Number.isFinite(phase) && phase >= plan.phase_ms,
    fresh_post_restore_nonce: clock ? fresh.length > 0 : null,
    recovery_within_budget: clock ? baseline && recovery !== null && recovery <= plan.recovery_gate_ms : null,
    native_and_adapters_unchanged: unchanged,
    all_successful_nonces_joined: successes.length > 0 && joined === successes.length,
    capture_no_reported_kernel_or_cap_failure: captureMetadataClean,
    capture_complete: captureMetadataClean ? accounting.verified : false,
    same_udp_tuple: tuples.verified
  };
  if (record.recovery_ms !== null && record.recovery_ms !== undefined &&
      record.recovery_ms !== rawRecovery) {
    errors.push('published recovery differs from fresh-post-restore proof');
  }
  return {
    id: group.id, kind: group.kind, integrity_errors: errors,
    missing_evidence: [...new Set(missing)], gates,
    warmup_ok: (record.warmup || []).filter(p => p.ok).length,
    phase_ok: (record.proofs || []).filter(p => p.ok).length,
    successful_nonce_joins: joined, raw_cross_clock_recovery_ms: rawRecovery,
    clock_adjusted_recovery_bounds_ms: fresh.length ? [recoveryLower, recovery] : null,
    recovery_measurement_scope: 'Delay to first definitely fresh sampled response; clock bounds do not locate the instant availability returned.',
    recovery_ms: recovery, vm_ahead_bounds_ms: clock ? [clock.lower, clock.upper] : null,
    straddling_successes: (record.proofs || []).filter(p => p.ok &&
      epoch(p.started) < ended && epoch(p.finished) >= ended).length,
    process_before: before, process_after: after, tuples, capture_accounting: accounting,
    runtime_errors: record.errors || []
  };
}

function auditRun(directory, serviceFile, clockFile) {
  const used = {};
  function read(file) {
    const absolute = path.resolve(file);
    const data = fs.readFileSync(absolute);
    used[absolute] = hash(data);
    return data.toString('utf8');
  }
  const start = JSON.parse(read(path.join(directory, 'run-start.json')));
  const status = JSON.parse(read(path.join(directory, 'status.json')));
  const records = JSON.parse(read(path.join(directory, 'trials.json')));
  const plan = start.plan;
  if (!plan || !Array.isArray(plan.groups) || plan.groups.length !== 4) throw Error('Expected frozen four-deployment plan');
  if (plan.groups.some(g => !/^[a-z0-9-]{1,64}$/.test(g.id) || !['v2', 'framed'].includes(g.kind)) ||
      new Set(plan.groups.map(g => g.id)).size !== 4) throw Error('Invalid/duplicate group assignment');
  const servicePath = serviceFile || path.join(directory, 'service.log');
  const services = fs.existsSync(servicePath) ? serviceProofs(read(servicePath)) : new Map();
  const errors = [], missing = [], seen = new Set();
  let clock = null;
  if (clockFile) {
    const observed = JSON.parse(read(clockFile));
    clock = {
      lower: observed.offset_envelope_lower_ms ?? observed.intersection_lower_ms,
      upper: observed.offset_envelope_upper_ms ?? observed.intersection_upper_ms
    };
    if (!Number.isFinite(clock.lower) || !Number.isFinite(clock.upper) || clock.lower > clock.upper) {
      throw Error('Invalid host/VM clock diagnostic bounds');
    }
  }
  if (status.status !== 'complete_engineering_checkpoint' || status.groups !== 4 || records.length !== 4) missing.push('finite checkpoint is incomplete');
  if (status.dpi_collection_authorized !== false) errors.push('stage A must not authorize fresh DPI collection');
  if (!services.size) missing.push('service-side proof log');
  const reports = [];
  for (const group of plan.groups) {
    const matches = records.filter(r => r.group && r.group.id === group.id);
    if (matches.length !== 1) { missing.push('exactly one record for ' + group.id); continue; }
    const snapshotPath = path.join(directory, group.id, 'snapshots.jsonl');
    const snapshots = fs.existsSync(snapshotPath) ?
      read(snapshotPath).trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
    reports.push(auditGroup(matches[0], group, plan, snapshots, services, seen, clock));
  }
  return {
    schema: 'belnet-g01-independent-stage-a-review/v1',
    auditor_sha256: hash(fs.readFileSync(__filename)),
    generated_at_utc: new Date().toISOString(),
    scope: 'Nonce, process continuity, framed tuple and capture integrity; not a complete acceptance verdict',
    integrity_errors: errors, missing_evidence: missing, groups: reports,
    input_sha256: used,
    limitations: [
      'No DPI efficacy/population claim; A is an engineering development checkpoint.',
      'Wire cost, queue delay, zero/large UDP smoke and raw-UDP firewall proof need separate evidence.',
      'V2 tuple identity requires separate UDP capture analysis.',
      'Process continuity checks process start ticks and adapter PIDs; no external process attestation.',
      'Clock-adjusted recovery assumes the supplied diagnostic offset bounds remain applicable; it is supplementary evidence, not frozen clock attestation.',
      'Published binary/source provenance is not rebuilt by this read-only audit.'
    ]
  };
}

if (require.main === module) {
  try {
    const argv = process.argv.slice(2), args = {};
    for (let i = 0; i < argv.length; i += 2) {
      if (!argv[i].startsWith('--') || argv[i + 1] === undefined) throw Error('Use --run DIR [--service-log FILE] [--clock FILE] [--out NEWFILE]');
      args[argv[i].slice(2)] = argv[i + 1];
    }
    if (!args.run) throw Error('Use --run DIR [--service-log FILE] [--clock FILE] [--out NEWFILE]');
    const report = auditRun(path.resolve(args.run), args['service-log'], args.clock);
    const output = JSON.stringify(report, null, 2) + '\n';
    if (args.out) fs.writeFileSync(path.resolve(args.out), output, { flag: 'wx', mode: 0o600 });
    else process.stdout.write(output);
    const invalid = report.integrity_errors.length || report.groups.some(g => g.integrity_errors.length);
    const incomplete = report.missing_evidence.length || report.groups.some(g => g.missing_evidence.length);
    if (invalid) process.exitCode = 1;
    else if (incomplete) process.exitCode = 2;
  } catch (error) { console.error(error.message); process.exitCode = 2; }
}

module.exports = { processIdentity, serviceProofs, freshProofs, framedTuples, outerCaptureAccounting, auditGroup, auditRun };

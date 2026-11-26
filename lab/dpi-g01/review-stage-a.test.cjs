'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { processIdentity, freshProofs, serviceProofs, framedTuples, outerCaptureAccounting, auditGroup } = require('./review-stage-a.cjs');

function identity(start) {
  const fields = ['S', ...Array(18).fill('0'), String(start), '0'];
  return '7\n8\n1 (belnet native) ' + fields.join(' ') + '\n';
}

test('process identity uses native start ticks, not changing CPU counters or PID alone', () => {
  const first = processIdentity(identity(111));
  const restarted = processIdentity(identity(222));
  assert.equal(first.native_pid, restarted.native_pid);
  assert.notEqual(first.native_start_ticks, restarted.native_start_ticks);
  assert.equal(processIdentity('broken output'), null);
  assert.deepEqual(first.adapters, ['7', '8']);
});

test('a success that straddles restore cannot prove a fresh post-restore request', () => {
  const ended = '2026-11-19T12:00:12Z';
  const record = {
    interruption: { interruption_ended: ended },
    proofs: [
      { ok: true, nonce: 'old', started: '2026-11-19T12:00:11Z', finished: '2026-11-19T12:00:13Z' },
      { ok: true, nonce: 'fresh', started: '2026-11-19T12:00:17Z', finished: '2026-11-19T12:00:18Z' },
      { ok: true, nonce: 'missing time', finished: '2026-11-19T12:00:14Z' }
    ]
  };
  assert.deepEqual(freshProofs(record).map(p => p.nonce), ['fresh']);
});

test('VM clock lead cannot turn a pre-restore request into a fresh request', () => {
  const record = {
    interruption: { interruption_ended: '2026-11-19T12:00:12.000Z' },
    proofs: [
      { ok: true, nonce: 'ambiguous', started: '2026-11-19T12:00:12.100Z', finished: '2026-11-19T12:00:13Z' },
      { ok: true, nonce: 'fresh', started: '2026-11-19T12:00:17Z', finished: '2026-11-19T12:00:18Z' }
    ]
  };
  assert.deepEqual(freshProofs(record).map(p => p.nonce), ['ambiguous', 'fresh']);
  assert.deepEqual(freshProofs(record, 148.025).map(p => p.nonce), ['fresh']);
});

test('service provenance keeps duplicates visible instead of silently deduplicating', () => {
  const nonce = 'a'.repeat(64);
  const matches = serviceProofs('proof nonce=' + nonce + ' bytes=4096 remote=x\n' +
    'proof nonce=' + nonce + ' bytes=16384 remote=y\n');
  assert.deepEqual(matches.get(nonce).map(p => p.bytes), [4096, 16384]);
});

test('G01 JSON service proofs retain server timestamps for request interval checks', () => {
  const nonce = 'b'.repeat(64), at = Date.parse('2026-11-19T12:00:14Z') * 1000;
  const matches = serviceProofs(JSON.stringify({ nonce, bytes: 1, at_unix_micros: at, utc: '2026-11-19T12:00:14Z' }));
  assert.equal(matches.get(nonce)[0].at_unix_micros, at);
  const group = { id: 'a01-v2', kind: 'v2', split: 'train' };
  const record = {
    group, warmup: [], app_baseline_conclusive: false,
    proofs: [{ index: 0, nonce, ok: true, requested_bytes: 1, body_bytes: 1, status: 200,
      started: '2026-11-19T12:00:12Z', finished: '2026-11-19T12:00:13Z' }]
  };
  const result = auditGroup(record, group, { warmup_start_ms: [], phase_fetch_start_ms: [0], proof_sizes: [1] },
    [], matches, new Set());
  assert.ok(result.integrity_errors.some(e => e.includes('outside client request time')));
});

test('the frozen per-deployment baseline schema is checked rather than assumed absent', () => {
  const group = { id: 'a01-v2', kind: 'v2', split: 'train' };
  const record = { group, warmup: [{ ok: true }], proofs: [], own_warmup_conclusive: true };
  const plan = { warmup_start_ms: [0], phase_fetch_start_ms: [], proof_sizes: [1] };
  const valid = auditGroup(record, group, plan, [], new Map(), new Set());
  assert.ok(!valid.integrity_errors.some(e => e.includes('baseline flag')));
  const wrong = auditGroup({ ...record, own_warmup_conclusive: false }, group, plan, [], new Map(), new Set());
  assert.ok(wrong.integrity_errors.some(e => e.includes('baseline flag')));
});

test('tuple proof requires both entries and the same SID at both boundaries', () => {
  function snapshot(label, changed) {
    return {
      label,
      clients: [1, 2].map(i => ({ ok: true, data: { connections: [{ connected: true, session_hash: 'sid' + i }] } })),
      servers: [1, 2].map(i => ({ ok: true, data: { connections: [{
        connected: true, session_hash: 'sid' + i, udp_tuple: '10.88.0.1' + i + ':' + (changed && i === 2 ? 6001 : 6000)
      }] } }))
    };
  }
  assert.equal(framedTuples([snapshot('pre-reset'), snapshot('phase-end')]).verified, true);
  assert.equal(framedTuples([snapshot('pre-reset'), snapshot('phase-end', true)]).verified, false);
  const censored = snapshot('phase-end');
  censored.servers[0].data.metadata_truncated = true;
  assert.equal(framedTuples([snapshot('pre-reset'), censored]).verified, false);
});

test('zero kernel drops does not turn unmatched outer counters into complete accounting', () => {
  const outer = { name: 'group-capture', captured: 1782, received_by_filter: 1797, dropped_by_kernel: 0 };
  const loopback = { name: 'group-udp1', captured: 374, received_by_filter: 748 };
  assert.equal(outerCaptureAccounting([outer, loopback]).verified, null);
  assert.equal(outerCaptureAccounting([{ ...outer, received_by_filter: 1782 }, loopback]).verified, true);
});

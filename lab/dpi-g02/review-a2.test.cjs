'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { freshVMProofs, queueAudit } = require('./review-a2.cjs');

function queueFixture(limit) {
  const expired = limit > 0;
  const up = [{ direction: 1, bytes: 5, input_unix_micros: 1000000, queue_wait_micros: 1000 }];
  if (!expired) up.unshift({ direction: 1, bytes: 5, input_unix_micros: 100000, queue_wait_micros: 300000 });
  return {
    metadata_truncated: false,
    connections: [{ max_queue_age_micros: limit, up_datagrams: up.length, up_bytes: up.length * 5,
      expired_datagrams: expired ? 1 : 0, expired_bytes: expired ? 5 : 0,
      failed_write_datagrams: 0, max_all_input_age_micros: 300000 }],
    packet_events: up,
    expired_events: expired ? [{ bytes: 5, age_micros: 300000, max_queue_age_micros: limit, reason: 'max_forward_age' }] : [],
    udp_inputs: [{ accepted: true, bytes: 5 }, { accepted: true, bytes: 5 }]
  };
}

test('expiry preserves loss and all-input age instead of inventing100ms delivery', () => {
  const r = queueAudit(queueFixture(100000), 100000);
  assert.deepEqual(r.errors, []);
  assert.equal(r.freshness_verified, true);
  assert.equal(r.expired_datagrams, 1);
  assert.equal(r.locally_written_datagrams, 1);
  assert.equal(r.max_all_consumed_input_age_micros, 300000);
  assert.equal(r.accepted_pending_or_unobserved, 0);
});

test('old forwarded payload cannot be hidden in an expired counter', () => {
  const data = queueFixture(100000);
  data.packet_events.push({ direction: 1, bytes: 5, input_unix_micros: 100000, queue_wait_micros: 300000 });
  data.connections[0].up_datagrams++;
  data.connections[0].up_bytes += 5;
  const r = queueAudit(data, 100000);
  assert.equal(r.freshness_verified, false);
  assert.ok(r.errors.some(e => e.includes('freshness limit')));
  assert.ok(r.errors.some(e => e.includes('exceed accepted')));
});

test('the frozen expiration schema uses max_queue_age_micros', () => {
  const data = queueFixture(100000);
  data.expired_events[0] = {
    at_unix_micros: 1795110801924559, input_unix_micros: 1795110800150046,
    connection: 2, session_hash: 'redacted', bytes: 5, age_micros: 1774512,
    max_queue_age_micros: 100000, reason: 'max_forward_age'
  };
  data.connections[0].max_all_input_age_micros = 1774512;
  assert.deepEqual(queueAudit(data, 100000).errors, []);
  delete data.expired_events[0].max_queue_age_micros;
  data.expired_events[0].limit_micros = 100000;
  assert.ok(queueAudit(data, 100000).errors.some(e => e.includes('age/limit')));
});

test('retain mode keeps old input and has no expiry freshness guarantee', () => {
  const r = queueAudit(queueFixture(0), 0);
  assert.deepEqual(r.errors, []);
  assert.equal(r.expired_datagrams, 0);
  assert.equal(r.locally_written_datagrams, 2);
  assert.equal(r.freshness_verified, null);
});

test('truncated metadata cannot validate the expiry contract', () => {
  const data = queueFixture(100000);
  data.metadata_truncated = true;
  assert.equal(queueAudit(data, 100000).freshness_verified, null);
});

test('VM microseconds determine fresh post-restore proof without host clock conversion', () => {
  const r = { interruption: { interruption_ended_unix_micros: 1000000 }, proofs: [
    { index: 0, ok: true, started_unix_micros: 999999, finished_unix_micros: 1001000 },
    { index: 1, ok: true, started_unix_micros: 1000000, finished_unix_micros: 1002000 }
  ] };
  assert.deepEqual(freshVMProofs(r).map(p => p.index), [1]);
});

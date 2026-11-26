'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {pairingCurve,analyze}=require('./reply-profile.cjs');
const events=gap=>Array.from({length:8},(_,i)=>[
  {at_micros:i*100000,direction:1},{at_micros:i*100000+gap,direction:-1}]).flat();
test('Declared lags include the exact boundary and preserve the denominator',()=>{
  assert.deepEqual(pairingCurve(events(10000)).counts,[0,0,8,8,8]);
  assert.deepEqual(pairingCurve(events(10001)).fractions,[0,0,0,1,1]);
});
test('Support limits abstain instead of returning false detection evidence',()=>{
  assert.equal(pairingCurve(events(1).slice(0,14)),null);
  assert.throws(()=>pairingCurve(Array(65).fill({at_micros:0,direction:1})),/bounded_event_array/);
});
test('Invalid timing, direction and unsafe precision are rejected rather than sorted or clamped',()=>{
  for(const e of [{at_micros:-1,direction:1},{at_micros:0,direction:0},
    {at_micros:2**54,direction:1}]) assert.throws(()=>pairingCurve([e]),/ordered_microsecond/);
  assert.throws(()=>pairingCurve([{at_micros:2,direction:1},{at_micros:1,direction:-1}]),/ordered_microsecond/);
});
test('Existing ten-ms score is independently crosschecked and test stages are rejected',()=>{
  const g={metadata:{group_id:'dev',split:'train',scope:'primary',class:'belnet'},coverage_complete:true,
    windows:[{eligible:true,ordering_ambiguous:false,scores:{r10:1},events:events(10000)}]};
  assert.equal(analyze({stage:'B1',scored_groups:[g]}).measurements[0].maximum_pair_fraction[2],1);
  g.windows[0].scores.r10=0;assert.throws(()=>analyze({stage:'B1',scored_groups:[g]}),/ten_ms_score_disagrees/);
  assert.throws(()=>analyze({stage:'B2',scored_groups:[]}),/development_B1_required/);
});

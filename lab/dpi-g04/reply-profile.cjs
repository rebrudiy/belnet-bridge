'use strict';
// Development-only descriptive statistics. No fit, network or enforcement.
const fs = require('node:fs');
const crypto = require('node:crypto');
const LAGS = Object.freeze([2000, 5000, 10000, 20000, 50000]);
function pairingCurve(events) {
  if (!Array.isArray(events) || events.length > 64) throw Error('bounded_event_array_required');
  let previous = -Infinity;
  for (const e of events) {
    if (!Number.isSafeInteger(e.at_micros) || e.at_micros < 0 || e.at_micros < previous ||
      ![1, -1].includes(e.direction)) throw Error('ordered_microsecond_events_required');
    previous = e.at_micros;
  }
  const up = events.filter(e => e.direction === 1).length;
  if (events.length < 16 || up < 8) return null;
  const counts = LAGS.map(() => 0);
  for (let i = 1; i < events.length; i++) {
    const a = events[i - 1], b = events[i];
    if (a.direction !== 1 || b.direction !== -1) continue;
    const gap = b.at_micros - a.at_micros;
    for (let k = 0; k < LAGS.length; k++) if (gap <= LAGS[k]) counts[k]++;
  }
  return {total_records:events.length, uplink_records:up,
    lags_micros:[...LAGS], counts, fractions:counts.map(n => n / up)};
}
function analyze(report) {
  if (report.stage !== 'B1' || !Array.isArray(report.scored_groups)) throw Error('development_B1_required');
  const groups = [];
  for (const g of report.scored_groups) {
    const m = g.metadata;
    if (m.split !== 'train') continue;
    if (m.scope !== 'primary' || !['benign','belnet'].includes(m.class)) throw Error('primary_train_required');
    const curves = [];
    for (const w of g.windows) {
      if (!w.eligible || w.ordering_ambiguous || !(w.scores?.r10 >= 0)) continue;
      const c = pairingCurve(w.events);
      if (!c || Math.abs(c.fractions[2] - w.scores.r10) > 1e-12) throw Error('ten_ms_score_disagrees');
      curves.push(c);
    }
    groups.push({group_id:m.group_id, class:m.class, split:'train',
      coverage_complete:g.coverage_complete, eligible_windows:curves.length,
      maximum_pair_fraction:LAGS.map((_, k) => curves.length ? Math.max(...curves.map(c=>c.fractions[k])) : null)});
  }
  return {kind:'measured_feature',split:'train',feature:'reply_lag_profile',
    definition:'Uplink immediately followed by downlink within each declared lag / all uplink records; same ordered max64 sample and >=16 total/>=8 uplink support as r10',
    lags_micros:[...LAGS],measurements:groups,
    limits:['Descriptive maxima across declared primary windows; no new threshold or policy calibrated',
      'Microsecond event fields only; raw nanosecond JSON is never re-encoded or used as an imprecise JavaScript number',
      'Incomplete groups remain incomplete; lack of eligible events is null, never a stealth verdict',
      'Selected after inspecting R1 development results; no heldout data read']};
}
if (require.main === module) {
  const [input, output] = process.argv.slice(2);
  if (!output || /vault|private[-_]test|b-test-|(?:^|[\\/])b2(?:[\\/]|$)/i.test(input)) throw Error('usage: reply-profile.cjs DEVELOPMENT_REPORT NEW_OUTPUT');
  const raw = fs.readFileSync(input), result = analyze(JSON.parse(raw));
  result.raw_evidence = {path:require('node:path').resolve(input),sha256:crypto.createHash('sha256').update(raw).digest('hex')};
  result.observed_at = new Date().toISOString();
  fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({train_groups:result.measurements.length,lags_micros:LAGS,fitting_performed:false}));
}
module.exports = {pairingCurve,analyze};

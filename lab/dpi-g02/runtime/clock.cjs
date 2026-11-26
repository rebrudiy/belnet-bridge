"use strict";
// These helpers never compare packet/proof ages against the macOS host clock.
function vmClock(sample) {
  if (
    !sample ||
    !Number.isSafeInteger(sample.unix_micros) ||
    sample.unix_micros <= 0 ||
    typeof sample.utc !== "string" ||
    !Number.isFinite(Date.parse(sample.utc)) ||
    Math.abs(Date.parse(sample.utc) * 1000 - sample.unix_micros) >= 1000
  )
    throw Error("Invalid VM clock sample");
  return sample;
}
function phaseWindow(sample, ms) {
  vmClock(sample);
  return {
    phase_started: sample.utc,
    phase_started_unix_micros: sample.unix_micros,
    phase_finished: new Date(
      (sample.unix_micros + ms * 1000) / 1000,
    ).toISOString(),
    phase_finished_unix_micros: sample.unix_micros + ms * 1000,
  };
}
function recovery(proofs, endMicros) {
  if (!Number.isSafeInteger(endMicros))
    return { first: null, straddling: [], recovery_micros: null };
  const after = proofs
    .filter(
      (p) =>
        p.ok === true &&
        Number.isSafeInteger(p.started_unix_micros) &&
        Number.isSafeInteger(p.finished_unix_micros) &&
        p.started_unix_micros >= endMicros &&
        p.finished_unix_micros >= p.started_unix_micros,
    )
    .sort((a, b) => a.finished_unix_micros - b.finished_unix_micros);
  return {
    first: after[0] || null,
    straddling: proofs.filter(
      (p) =>
        p.ok === true &&
        p.started_unix_micros < endMicros &&
        p.finished_unix_micros >= endMicros,
    ),
    recovery_micros: after.length
      ? after[0].finished_unix_micros - endMicros
      : null,
  };
}
module.exports = { vmClock, phaseWindow, recovery };

'use strict';
const fs = require('node:fs');
const { validateLedger, planNativeRound } = require('./index.cjs');
const [mode, file, cycle, candidate] = process.argv.slice(2);
const read = (p) => JSON.parse(fs.readFileSync(p));
try {
  let result;
  if (mode === 'validate') result = validateLedger(read(file));
  else if (mode === 'plan')
    result = planNativeRound(read(file), Number(cycle), read(candidate));
  else throw Error('Use validate LEDGER | plan LEDGER CYCLE CANDIDATE_JSON');
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
} catch (e) {
  console.error(e.message);
  process.exitCode = 1;
}

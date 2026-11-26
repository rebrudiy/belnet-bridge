'use strict';
// Derive a companion from our NEW header parser; never alter frozen G03 sources.
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const dir = __dirname,
  observer = path.join(dir, '../observer');
const raw = fs.readFileSync(path.join(observer, 'main.go'));
let s = raw.toString();
const replace = (a, b) => {
  if (!s.includes(a)) throw Error('Parser derivation anchor missing:' + a);
  s = s.replace(a, b);
};
replace('\t"encoding/json"\n', '');
replace('\t"flag"\n', '');
replace('type Report struct {', 'type Report struct {\n long *collector');
replace('type Parser struct {', 'type Parser struct {\n aggregates *collector');
replace(
  '\treturn p, nil\n}',
  '\tp.aggregates = newCollector(p.measurementStart, p.measurementEnd)\n\treturn p, nil\n}'
);
replace(
  '\tp.recordOrdinal++',
  '\tif p.aggregates != nil { p.aggregates.record(flow.ID,direction,size,at) }\n\tp.recordOrdinal++'
);
replace(
  '\treport.PCAPSHA = pcapSHA',
  '\treport.PCAPSHA = pcapSHA\n\treport.long = p.aggregates'
);
const main = s.indexOf('\nfunc main() {');
if (main < 0) throw Error('Parser CLI boundary missing');
s = s.slice(0, main) + '\n';
fs.writeFileSync(path.join(dir, 'pcap.go'), s);
const sha = crypto.createHash('sha256').update(raw).digest('hex');
fs.writeFileSync(
  path.join(dir, 'baseline.go'),
  'package main\n\nconst ParserBaselineSHA = "' +
    sha +
    '"\nconst LongflowVersion = "g04-header-longflow-v1"\n'
);
for (const file of fs.readdirSync(observer)) {
  if (
    file.endsWith('_test.go') ||
    [
      'header.go',
      'coverage.go',
      'ordering.go',
      'coverage-contract.json',
      'ordering-contract.json'
    ].includes(file)
  )
    fs.copyFileSync(path.join(observer, file), path.join(dir, file));
}
console.log(
  JSON.stringify({ parser_source_sha256: sha, actual_data_read: false })
);

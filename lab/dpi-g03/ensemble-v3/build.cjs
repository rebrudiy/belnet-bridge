'use strict';
// Offline source preparation only; no real cohort read, fit or network.
const fs = require('fs'), path = require('path'), crypto = require('crypto'), cp = require('child_process');
const root = process.cwd(), dir = path.relative(root, __dirname), out = path.join(dir, 'tooling');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const run = (args, env = {}) => cp.execFileSync('go', args, {cwd: root, env: {...process.env, ...env}, encoding: 'utf8'});
const load = file => JSON.parse(fs.readFileSync(file));
fs.mkdirSync(out, {recursive: true});
fs.writeFileSync(path.join(out, 'race-test.log'), run(['test', '-race', '-count=1', '-v', './' + dir]));
fs.writeFileSync(path.join(out, 'vet.log'), run(['vet', './' + dir]));
const source = {}, archive = {};
fs.mkdirSync(path.join(out, 'source-archive'), {recursive: true});
for (const file of fs.readdirSync(dir).filter(f => /\.(go|json|md|cjs)$/.test(f)).sort()) {
  const original = path.join(dir, file), bytes = fs.readFileSync(original);
  source[original] = hash(bytes);
  fs.writeFileSync(path.join(out, 'source-archive', file), bytes);
  archive[path.join('source-archive', file)] = hash(bytes);
}
const binary = {};
for (const os of ['darwin', 'linux']) {
  const tmp = path.join(out, `ensemble-${os}-arm64`);
  run(['build', '-trimpath', '-o', tmp, './' + dir], {GOOS: os, GOARCH: 'arm64', CGO_ENABLED: '0'});
  const sha = hash(fs.readFileSync(tmp)), versioned = path.join(out, `ensemble-g03-v3-${os}-arm64-${sha.slice(0,12)}`);
  fs.copyFileSync(tmp, versioned + '.tmp'); fs.chmodSync(versioned + '.tmp', 0o755); fs.renameSync(versioned + '.tmp', versioned);
  binary[os === 'darwin' ? 'ensemble' : 'ensemble-linux-arm64'] = {sha256: sha, versioned_path: versioned};
}
const observer = load('lab/dpi-g03/observer-v4/tooling/TOOLING.json');
const longflow = load('lab/dpi-g03/longflow-v4/tooling/TOOLING.json');
const previous = load('lab/dpi-g03/ensemble/tooling/TOOLING.json');
const score_engine = previous.score_engine;
if (hash(fs.readFileSync(score_engine.versioned_path)) !== score_engine.sha256) throw Error('Score engine drift');
const catalogPath = path.join(out, 'catalog.json');
cp.execFileSync(path.resolve(binary.ensemble.versioned_path), ['catalog', '-engine', path.resolve(score_engine.versioned_path), '-ordering-sha', observer.ordering_semantics_sha256, '-coverage-sha', observer.coverage_semantics_sha256, '-out', catalogPath]);
const catalog = load(catalogPath);
const descriptor = {
  schema: 4, version: 'g03-ensemble-v3', status: 'SOURCE_READY_SYNTHETIC_TESTED_NO_REAL_FIT', created_at: new Date().toISOString(),
  source_sha256: source, source_archive_sha256: archive, source_archive_aggregate_sha256: hash(JSON.stringify(archive)), binary, score_engine,
  definitions_sha256: catalog.definitions_sha256, window_definitions_sha256: previous.window_definitions_sha256,
  longflow_definitions_sha256: longflow.feature_definitions_sha256,
  ordering_semantics_sha256: observer.ordering_semantics_sha256, coverage_semantics_sha256: observer.coverage_semantics_sha256,
  observer_descriptor_sha256: hash(fs.readFileSync('lab/dpi-g03/observer-v4/tooling/TOOLING.json')),
  longflow_descriptor_sha256: hash(fs.readFileSync('lab/dpi-g03/longflow-v4/tooling/TOOLING.json')),
  checks: {race: 'PASS race-test.log', vet: 'PASS vet.log', actual_data_read_or_fitted: false},
  go_version: run(['version']).trim()
};
if (!descriptor.definitions_sha256 || catalog.rules.length !== 23) throw Error('Expected exactly23 rules');
fs.writeFileSync(path.join(out, 'TOOLING.json'), JSON.stringify(descriptor, null, 2) + '\n');
console.log(JSON.stringify({manifest: path.join(out, 'TOOLING.json'), binary, definitions_sha256: descriptor.definitions_sha256}, null, 2));

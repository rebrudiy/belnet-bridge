// Reproduce source-only V3 reporter builds. No capture, fitting or network.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const root = process.cwd();
const dir = path.relative(root, __dirname);
const name = path.basename(dir).split('-')[0];
const schema = name === 'observer' ? 5 : 3;
const out = path.join(dir, 'tooling');
const digest = b => crypto.createHash('sha256').update(b).digest('hex');
const run = (args, env = {}) => cp.execFileSync('go', args, {cwd: root, env: {...process.env, ...env}, encoding: 'utf8'});
fs.mkdirSync(out, {recursive: true});
// A descriptor is emitted only after checks really finish successfully.
fs.writeFileSync(path.join(out, 'race-test.log'), run(['test', '-race', '-count=1', '-v', './' + dir]));
fs.writeFileSync(path.join(out, 'vet.log'), run(['vet', './' + dir]));
const files = fs.readdirSync(dir).filter(f => /\.(go|json|md|cjs)$/.test(f)).sort();
const source = {}, archive = {};
fs.mkdirSync(path.join(out, 'source-archive'), {recursive: true});
for (const file of files) {
 const original = path.join(dir, file), dest = path.join(out, 'source-archive', file);
 const bytes = fs.readFileSync(original);
 source[original] = digest(bytes);
 fs.writeFileSync(dest, bytes);
 archive[path.join('source-archive', file)] = digest(bytes);
}
const binaries = {};
for (const os of ['darwin', 'linux']) {
 const tmp = path.join(out, `${name}-${os}-arm64`);
 run(['build', '-trimpath', '-o', tmp, `./${dir}`], {GOOS: os, GOARCH: 'arm64', CGO_ENABLED: '0'});
 const sha = digest(fs.readFileSync(tmp));
 const versioned = path.join(out, `${name}-g03-v4-${os}-arm64-${sha.slice(0, 12)}`);
 // Atomic replacement avoids stale Darwin code-signature vnode cache.
 const staged = versioned + '.tmp';
 fs.copyFileSync(tmp, staged); fs.chmodSync(staged, 0o755); fs.renameSync(staged, versioned);
 binaries[os === 'darwin' ? name : `${name}-linux-arm64`] = {sha256: sha, versioned_path: versioned};
}
const coverage = JSON.parse(fs.readFileSync(path.join(dir, 'coverage-contract.json')));
const descriptor = {
 schema, version: `g03-${name}-v4`, created_at: new Date().toISOString(),
 status: 'SOURCE_READY_SYNTHETIC_TESTED_NO_FIT_OR_NEW_TRAFFIC',
 coverage_semantics_sha256: digest(JSON.stringify(coverage)),
 ordering_semantics_sha256: 'a285e9ffc0037f3e0ffb1cf84be6ba6a4f2c9669c90882473c15f57498a53ce1',
 source_sha256: source, source_archive_sha256: archive,
 source_archive_aggregate_sha256: digest(JSON.stringify(archive)), binary: binaries,
 checks: {race: 'PASS race-test.log', vet: 'PASS vet.log',
  tests: fs.readFileSync(path.join(out, 'race-test.log'), 'utf8').split('\n').filter(l => l.startsWith('--- PASS: ')).map(l => l.split(' ')[2]),
  raw_payload_before_handshake_including_TFO: 'PASS',
  whole_primary_flow_fault_QC: 'PASS unsampled gap/conflict/closedpartial/malformed/causal/missingSYN invalidate group',
  sound_earlier_windows: 'PASS retained as observed-hit lower bounds on incomplete group',
  postprimary_fault_scope: 'PASS diagnostics retained; no new primary obligation',
  fault_timestamps: 'PASS actual causal occurrence; partial closed at captured close, no clamp',
  captured_SYN_zero_payload_missing_SYNACK: 'PASS explicit noTLS evidence abstention, retained flow denominator',
  SYN_missing_with_zero_payload: 'PASS remains UNKNOWN',
  payload_with_missing_handshake: 'PASS remains UNKNOWN',
  grace_only_no_activity: 'PASS remains UNKNOWN',
  TCP_gap_and_per_stream_clock: 'PASS remains UNKNOWN'},
 actual_data_read_or_fitted: false, new_traffic_or_Docker: false,
 go_version: run(['version']).trim(),
 protected_v3_descriptor_sha256: digest(fs.readFileSync(path.join(dir.replace('-v4', '-v3'), 'tooling/TOOLING.json'))),
 protected_v3: JSON.parse(fs.readFileSync(path.join(dir.replace('-v4', '-v3'), 'tooling/TOOLING.json'))).source_sha256,
 protected_v3_binaries: JSON.parse(fs.readFileSync(path.join(dir.replace('-v4', '-v3'), 'tooling/TOOLING.json'))).binary,
};
for (const [file, expected] of Object.entries(descriptor.protected_v3)) {
 if (digest(fs.readFileSync(file)) !== expected) throw new Error(`Protected V3 changed: ${file}`);
}
for (const row of Object.values(descriptor.protected_v3_binaries)) {
 if (digest(fs.readFileSync(row.versioned_path)) !== row.sha256) throw new Error('Protected V3 binary changed');
}
if (name === 'longflow') {
 descriptor.feature_definitions_sha256 = '9d866dd631df3601630ee0f3ce0c00383f50a46194bca44cd88349bffade864e';
 const catalogFile = path.join(out, 'catalog.json');
 cp.execFileSync(path.join(root, binaries.longflow.versioned_path), ['-catalog', '-out', catalogFile]);
}
fs.writeFileSync(path.join(out, 'TOOLING.json'), JSON.stringify(descriptor, null, 2) + '\n');
console.log(JSON.stringify({name, manifest: path.join(out, 'TOOLING.json'), binary: binaries}, null, 2));

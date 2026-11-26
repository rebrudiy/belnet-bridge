'use strict';
// Source/synthetic preparation only. No actual PCAP, fit, Docker or network.
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto'),
  cp = require('node:child_process');
const root = process.cwd(),
  dir = path.relative(root, __dirname),
  name = path.basename(dir),
  out = path.join(dir, 'tooling');
const hash = (b) => crypto.createHash('sha256').update(b).digest('hex');
const run = (args, env = {}) =>
  cp.execFileSync('go', args, {
    cwd: root,
    env: { ...process.env, ...env },
    encoding: 'utf8'
  });
if (name === 'longflow') {
  cp.execFileSync(process.execPath, [path.join(dir, 'sync-parser.cjs')], {
    cwd: root
  });
  run(['fmt', './' + dir]);
}
fs.mkdirSync(out, { recursive: true });
const protectedG03 = {};
for (const sourceName of ['observer', 'longflow']) {
  const descriptor = JSON.parse(
    fs.readFileSync(`lab/dpi-g03/${sourceName}-v4/tooling/TOOLING.json`)
  );
  for (const [file, expected] of Object.entries(descriptor.source_sha256)) {
    if (hash(fs.readFileSync(file)) !== expected)
      throw Error('Frozen G03 source changed:' + file);
    protectedG03[file] = expected;
  }
  for (const b of Object.values(descriptor.binary)) {
    if (hash(fs.readFileSync(b.versioned_path)) !== b.sha256)
      throw Error('Frozen G03 binary changed');
    protectedG03[b.versioned_path] = b.sha256;
  }
}
fs.writeFileSync(
  path.join(out, 'race-test.log'),
  run(['test', '-race', '-count=1', '-v', './' + dir])
);
fs.writeFileSync(path.join(out, 'vet.log'), run(['vet', './' + dir]));
const source = {},
  archive = {};
fs.mkdirSync(path.join(out, 'source-archive'), { recursive: true });
for (const file of fs
  .readdirSync(dir)
  .filter((f) => /\.(go|json|md|cjs)$/.test(f))
  .sort()) {
  const original = path.join(dir, file),
    raw = fs.readFileSync(original);
  source[original] = hash(raw);
  fs.writeFileSync(path.join(out, 'source-archive', file), raw);
  archive['source-archive/' + file] = hash(raw);
}
const binary = {};
for (const os of ['darwin', 'linux']) {
  const tmp = path.join(out, `${name}-${os}-arm64`);
  run(['build', '-trimpath', '-o', tmp, './' + dir], {
    GOOS: os,
    GOARCH: 'arm64',
    CGO_ENABLED: '0'
  });
  const sha = hash(fs.readFileSync(tmp)),
    versioned = path.join(
      out,
      `${name}-g04-header-v1-${os}-arm64-${sha.slice(0, 12)}`
    );
  fs.copyFileSync(tmp, versioned + '.tmp');
  fs.chmodSync(versioned + '.tmp', 0o755);
  fs.renameSync(versioned + '.tmp', versioned);
  binary[os === 'darwin' ? name : name + '-linux-arm64'] = {
    sha256: sha,
    versioned_path: versioned
  };
}
const coverage = JSON.parse(
    fs.readFileSync(path.join(dir, 'coverage-contract.json'))
  ),
  ordering = JSON.parse(
    fs.readFileSync(path.join(dir, 'ordering-contract.json'))
  );
const descriptor = {
  schema: name === 'observer' ? 6 : 4,
  version: `g04-header-${name}-v1`,
  created_at: new Date().toISOString(),
  status: 'SOURCE_READY_SYNTHETIC_ONLY_NO_ACTUAL_DATA',
  evidence_unit: 'tls23_header_declared_length',
  coverage_semantics_sha256: hash(JSON.stringify(coverage)),
  ordering_semantics_sha256: hash(JSON.stringify(ordering)),
  source_sha256: source,
  source_archive_sha256: archive,
  source_archive_aggregate_sha256: hash(JSON.stringify(archive)),
  binary,
  protected_g03_sha256: protectedG03,
  checks: {
    race: 'PASS race-test.log',
    vet: 'PASS vet.log',
    tests: fs
      .readFileSync(path.join(out, 'race-test.log'), 'utf8')
      .split('\n')
      .filter((l) => l.startsWith('--- PASS: '))
      .map((l) => l.split(' ')[2]),
    actual_data_read: false,
    classifier_fitting: false,
    Docker_or_network: false
  },
  bounds: {
    raw_pcap_bytes: 268435456,
    consumed_history_logical_bytes_per_pass: 268435456,
    pending_global_bytes: 8388608,
    max_flows: 512,
    selection_per_window: 64,
    observation:
      'two-pass offline SHADOW; heap overhead and two-pass working memory additional'
  },
  go_version: run(['version']).trim(),
  module_sha256: Object.fromEntries(
    ['go.mod', 'go.sum'].map((f) => [f, hash(fs.readFileSync(f))])
  )
};
if (name === 'longflow') {
  const catalog = path.join(out, 'catalog.json');
  cp.execFileSync(path.resolve(binary.longflow.versioned_path), [
    '-catalog',
    '-out',
    catalog
  ]);
  descriptor.feature_definitions_sha256 = JSON.parse(
    fs.readFileSync(catalog)
  ).definitions_sha256;
  descriptor.parser_baseline_source_sha256 = hash(
    fs.readFileSync('lab/dpi-g04/observer/main.go')
  );
}
fs.writeFileSync(
  path.join(out, 'TOOLING.json'),
  JSON.stringify(descriptor, null, 2) + '\n'
);
console.log(
  JSON.stringify({
    manifest: path.join(out, 'TOOLING.json'),
    schema: descriptor.schema,
    version: descriptor.version,
    binary,
    coverage: descriptor.coverage_semantics_sha256,
    ordering: descriptor.ordering_semantics_sha256,
    definitions: descriptor.feature_definitions_sha256
  })
);

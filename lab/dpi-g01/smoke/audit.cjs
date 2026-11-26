"use strict";
// Passive re-analysis only. Original result and its instrumentation errors remain.
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto"),
  assert = require("node:assert/strict");
const ROOT = path.resolve(__dirname, "../../.."),
  id = process.argv[2] || "isolated-20261119-01",
  base = path.join(ROOT, "out/dpi-g01/smoke", id),
  read = (n) => JSON.parse(fs.readFileSync(path.join(base, n))),
  hash = (p) =>
    crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const r = read("result.json"),
  freeze = read("freeze.json"),
  index = read("artifacts.json");
for (const [f, h] of Object.entries(index))
  assert.equal(hash(path.join(base, f)), h);
for (const [f, h] of Object.entries(freeze.source_sha256)) {
  const current = path.join(ROOT, f),
    archived = path.join(base, "source-snapshot", f);
  assert.ok(
    (fs.existsSync(current) && hash(current) === h) ||
      (fs.existsSync(archived) && hash(archived) === h),
    "Original frozen acquisition source unavailable: " + f,
  );
}
const names = [
    "server-before-restart.json",
    "server-after-restart.json",
    "server-two-sids.json",
    "server-after-bad-token.json",
  ],
  states = names.map(read);
const pairs = (s) =>
  Object.fromEntries(
    s.connections
      .filter((c) => c.session_hash && c.udp_tuple)
      .map((c) => [c.session_hash, c.udp_tuple]),
  );
const before = pairs(states[0]),
  after = pairs(states[1]),
  two = pairs(states[2]),
  bad = pairs(states[3]);
const same = (a, b) =>
  JSON.stringify(Object.entries(a).sort()) ===
  JSON.stringify(Object.entries(b).sort());
const primary = r.attempts.filter(
    (a) => a.phase === "before_restart" || a.phase === "after_restart",
  ),
  expected = [0, 1, 1200, 60000, 65507];
const perPhase = {};
for (const phase of ["before_restart", "after_restart"]) {
  const a = primary.filter((a) => a.phase === phase);
  perPhase[phase] = {
    sizes: a.map((a) => a.bytes),
    exact:
      a.length === 5 &&
      a.every(
        (x, i) =>
          x.bytes === expected[i] &&
          x.received_bytes === x.bytes &&
          x.ok === true,
      ),
  };
}
const echo = fs
    .readFileSync(path.join(base, "echo.jsonl"), "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse),
  uniquePeers = [...new Set(echo.map((e) => e.peer))];
const token = fs
  .readFileSync(
    path.join(ROOT, "lab/dpi-g01/run/prepared-a/private/bridge-token"),
  )
  .toString()
  .trim();
const exportedTokenMatches = Object.keys(index).filter((f) =>
  fs.readFileSync(path.join(base, f)).includes(Buffer.from(token)),
);
const schemaErrors = r.errors.filter(
  (e) =>
    e ===
    "json: cannot unmarshal bool into Go struct field state.metadata_truncated of type uint64",
);
const allKnownSchemaErrors =
  schemaErrors.length === r.errors.length && schemaErrors.length === 4;
const gates = {
  exact_before: perPhase.before_restart.exact,
  exact_after: perPhase.after_restart.exact,
  primary_udp_source_stable: new Set(primary.map((a) => a.source)).size === 1,
  server_sid_tuple_preserved:
    Object.keys(before).length === 1 && same(before, after),
  two_sids_isolated:
    Object.keys(two).length === 2 && new Set(Object.values(two)).size === 2,
  bad_token_no_udp_state:
    same(two, bad) &&
    states[2].packet_events.length === states[3].packet_events.length &&
    r.attempts.find((a) => a.phase === "bad_token")?.ok === false,
  go_processes_unchanged:
    same(r.adapter_pids_before, r.adapter_pids_after) &&
    Object.keys(r.adapter_pids_before).length === 3,
  core_restarted: r.restart.old_pid !== r.restart.new_pid,
  metadata_complete: states.every((s) => s.metadata_truncated === false),
  echo_exactly_expected:
    echo.length === 11 &&
    echo.filter((e) => e.bytes === 0).length === 2 &&
    echo.filter((e) => e.bytes === 65507).length === 2 &&
    uniquePeers.length === 2,
  no_token_export: exportedTokenMatches.length === 0,
};
const firstAfter = primary.find((a) => a.phase === "after_restart"),
  audit = {
    schema: "g01-isolated-smoke-passive-audit/v1",
    audited_at: new Date().toISOString(),
    native_belnet: false,
    fixture_only: true,
    original_helper_passed: r.passed,
    original_helper_errors: r.errors,
    known_helper_schema_issue: allKnownSchemaErrors,
    correction:
      "Read raw state.metadata_truncated as actual bool; keep original helper result=false and all four errors immutable. No network rerun or changed wire outcomes.",
    gates,
    functional_checks_passed: Object.values(gates).every(Boolean),
    all_non_schema_errors: r.errors.filter((e) => !schemaErrors.includes(e)),
    per_phase: perPhase,
    primary_source: r.primary_udp_source,
    primary_session_tuple: before,
    second_session_tuples: two,
    echo_peers: uniquePeers,
    core_absent_ms:
      Date.parse(r.restart.restart_started) -
      Date.parse(r.restart.absent_started),
    first_post_restart_roundtrip_ms: firstAfter.elapsed_micros / 1000,
    first_post_restart_completion_after_core_start_ms:
      (firstAfter.started_unix_micros +
        firstAfter.elapsed_micros -
        Date.parse(r.restart.restart_started) * 1000) /
      1000,
    capture: {
      bytes: fs.statSync(path.join(base, "outer.pcap")).size,
      log: fs.readFileSync(path.join(base, "capture.log"), "utf8"),
      scope:
        "loopback TCP19444 only; kernel drop counter0 does not itself prove complete tail capture",
    },
    original_artifacts_verified: Object.keys(index).length,
    original_source_hashes_verified: Object.keys(freeze.source_sha256).length,
    freeze_precedes_container_start: read("runtime.json").freeze_precedes_start,
    audit_source_sha256: hash(__filename),
    original_artifact_index_sha256: hash(path.join(base, "artifacts.json")),
  };
fs.writeFileSync(
  path.join(base, "audit-corrected.json"),
  JSON.stringify(audit, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    functional_checks_passed: audit.functional_checks_passed,
    original_helper_passed: r.passed,
    known_schema_issue: allKnownSchemaErrors,
    gates,
    core_absent_ms: audit.core_absent_ms,
    first_post_restart_completion_after_core_start_ms:
      audit.first_post_restart_completion_after_core_start_ms,
    artifact_index_sha256: audit.original_artifact_index_sha256,
  }),
);

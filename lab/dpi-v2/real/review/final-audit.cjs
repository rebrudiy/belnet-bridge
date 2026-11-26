"use strict";
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const ROOT = process.cwd(),
  OUT = "out/dpi-v2/audit";
const read = (p) => JSON.parse(fs.readFileSync(p)),
  sha = (p) =>
    crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const inputs = [
  "out/dpi-v2/dataset-final.json",
  "out/dpi-v2/late-dataset-final.json",
  "out/dpi-v2/native/trials.json",
  "out/dpi-v2/rounds/trials.json",
  "out/dpi-v2/forest-final/report.json",
  "out/dpi-v2/classical-series/final/early-all-heldout.json",
  "out/dpi-v2/diagnostic-controls.json",
  "lab/dpi-v2/run/service-http.log",
];
const before = Object.fromEntries(inputs.map((p) => [p, sha(p)]));
const data = read(inputs[0]),
  late = read(inputs[1]),
  native = read(inputs[2]),
  rounds = read(inputs[3]),
  forest = read(inputs[4]),
  classical = read(inputs[5]),
  diag = read(inputs[6]);
const collisions = [],
  duplicateSessions = [],
  groups = new Map(),
  seen = new Map();
for (const [window, rows] of [
  ["early", data],
  ["late", late],
])
  for (const o of rows) {
    const g = groups.get(o.group_id);
    if (g && g.split !== o.split)
      collisions.push({
        group: o.group_id,
        splits: [g.split, o.split],
        window,
      });
    else groups.set(o.group_id, { split: o.split, class: o.class });
    const id = window + "/" + o.session_id;
    if (seen.has(id)) duplicateSessions.push(id);
    seen.set(id, true);
  }
function summary(rows) {
  const counts = {};
  for (const o of rows) {
    const domain = o.profile.startsWith("real")
      ? "real-browser"
      : o.class === "belnet"
        ? "native"
        : "local-matched";
    const k = o.split + "/" + o.class + "/" + domain;
    counts[k] = (counts[k] || 0) + 1;
  }
  return {
    flows: rows.length,
    groups: new Set(rows.map((o) => o.group_id)).size,
    counts,
  };
}
const localFiles = fs
    .readdirSync("lab/dpi-v2/run/controls-final")
    .filter((n) => /^fresh-local-.*\.json$/.test(n)),
  localSources = localFiles.map((n) =>
    read("lab/dpi-v2/run/controls-final/" + n),
  );
const diagnosticIds = new Set(diag.map((x) => x.observation.session_id)),
  diagnosticGroups = new Set(diag.map((x) => x.observation.group_id));
const metadata = {};
for (const [name, rows] of [
  [
    "fresh_final_local",
    data.filter((o) => o.class === "benign" && !o.profile.startsWith("real")),
  ],
  ["native", data.filter((o) => o.class === "belnet")],
  ["diagnostic", diag.map((x) => x.observation)],
]) {
  metadata[name] = {};
  for (const o of rows) {
    const k = o.events
      .filter((e) => e.direction === 1)
      .slice(0, 3)
      .map((e) => e.bytes)
      .join(",");
    metadata[name][k] = (metadata[name][k] || 0) + 1;
  }
}
const localById = new Map(
  localSources.map((x) => [x.observation.session_id, x]),
);
const matchingErrors = data
  .filter((o) => o.profile.startsWith("local"))
  .filter(
    (o) =>
      !localById.has(o.session_id) ||
      JSON.stringify(localById.get(o.session_id).observation.events) !==
        JSON.stringify(o.events),
  )
  .map((o) => o.session_id);
const fingerprints = new Map();
for (const o of data) {
  const h = crypto
    .createHash("sha256")
    .update(JSON.stringify(o.events))
    .digest("hex");
  if (!fingerprints.has(h)) fingerprints.set(h, []);
  fingerprints.get(h).push(o);
}
const repeatedAcrossSplits = [...fingerprints]
  .filter(([, a]) => new Set(a.map((o) => o.split)).size > 1)
  .map(([hash, a]) => ({
    hash,
    flows: a.length,
    records: a[0].events.length,
    classes: [...new Set(a.map((o) => o.class))],
    splits: [...new Set(a.map((o) => o.split))],
  }));
const proofLogs = new Map();
for (const line of fs.readFileSync(inputs[7], "utf8").split("\n")) {
  const m = line.match(/proof nonce=([a-f0-9]{64}) bytes=(\d+)/);
  if (m) {
    const a = proofLogs.get(m[1]) || [];
    a.push({ bytes: Number(m[2]), line });
    proofLogs.set(m[1], a);
  }
}
const nonceChecks = [];
for (const [run, rows] of [
  ["native", native],
  ["rounds", rounds],
])
  for (const row of rows)
    for (const p of row.proofs || []) {
      const matches = proofLogs.get(p.nonce) || [];
      nonceChecks.push({
        run,
        group: row.id,
        nonce: p.nonce,
        ok: p.ok,
        body_bytes: p.body_bytes,
        service_log_matches: matches.length,
        service_size_match:
          !p.ok || matches.some((m) => m.bytes === p.body_bytes),
      });
    }
function cost(row) {
  let wire = 0,
    udp = 0,
    rejected = 0,
    aborted = 0,
    pending = 0,
    queuedBytes = 0,
    maxQueueDatagrams = 0,
    maxQueueBytes = 0,
    maxWait = 0,
    maxAge = 0;
  for (const s of row.states || []) {
    wire += (s.wire_bytes?.up || 0) + (s.wire_bytes?.down || 0);
    udp += (s.udp_bytes?.up || 0) + (s.udp_bytes?.down || 0);
    for (const x of s.cell_stats || []) {
      rejected += x.rejected_datagrams || 0;
      aborted += x.aborted_datagrams || 0;
      pending += x.queue_datagrams || 0;
      queuedBytes += x.queue_bytes || 0;
      maxQueueDatagrams = Math.max(
        maxQueueDatagrams,
        x.max_queue_datagrams || 0,
      );
      maxQueueBytes = Math.max(maxQueueBytes, x.max_queue_bytes || 0);
      maxWait = Math.max(maxWait, x.max_queue_wait_micros || 0);
      maxAge = Math.max(maxAge, x.max_datagram_age_micros || 0);
    }
    for (const x of s.shaping_stats || []) {
      maxWait = Math.max(maxWait, x.max_queue_delay_micros || 0);
      maxQueueDatagrams = Math.max(
        maxQueueDatagrams,
        x.max_queue_datagrams || 0,
      );
      maxQueueBytes = Math.max(maxQueueBytes, x.max_queue_bytes || 0);
    }
  }
  return {
    group: row.id,
    kind: row.kind,
    round: row.round,
    wire_bytes: wire,
    admitted_up_plus_delivered_down_udp_bytes: udp,
    ciphertext_to_udp_ratio: udp ? wire / udp : null,
    over8x: udp ? wire / udp > 8 : null,
    wire_exceeds8_times_udp: wire > 8 * udp,
    no_native_payload_observed: udp === 0,
    ratio_status: udp
      ? "finite"
      : wire
        ? "undefined_positive_wire_zero_udp"
        : "no_bytes",
    max_client_queue_wait_micros: maxWait,
    max_client_datagram_age_micros: maxAge,
    over100ms: udp ? maxWait > 100000 || maxAge > 100000 : null,
    rejected_datagrams: rejected,
    aborted_datagrams: aborted,
    pending_datagrams_at_snapshot: pending,
    pending_bytes_at_snapshot: queuedBytes,
    max_client_queue_datagrams: maxQueueDatagrams,
    max_client_queue_bytes: maxQueueBytes,
    http_ok: (row.proofs || []).filter((p) => p.ok).length,
    http_attempts: (row.proofs || []).length,
  };
}
const costs = rounds.map(cost),
  roundCosts = [];
const zeroPayloadGroups = new Set(
  costs.filter((x) => x.no_native_payload_observed).map((x) => x.group),
);
const positiveScope = {
  zero_payload_groups: [...zeroPayloadGroups],
  dataset_positive_flows_without_group_udp_payload: data.filter(
    (o) => o.class === "belnet" && zeroPayloadGroups.has(o.group_id),
  ).length,
  test_positive_flows_without_group_udp_payload: data.filter(
    (o) =>
      o.class === "belnet" &&
      o.split === "test" &&
      zeroPayloadGroups.has(o.group_id),
  ).length,
  interpretation:
    "Preserved positive wrapper-attempt labels are not all evidence of real BelNet payload; r14g3/r15 have ciphertext-only idlecover, no admitted/delivered native UDP. Do not silently drop or relabel after scoring.",
};
for (let n = 1; n <= 15; n++) {
  const rows = costs.filter((x) => x.round === n),
    wire = rows.reduce((n, x) => n + x.wire_bytes, 0),
    udp = rows.reduce(
      (n, x) => n + x.admitted_up_plus_delivered_down_udp_bytes,
      0,
    );
  roundCosts.push({
    round: n,
    kind: rows[0]?.kind,
    http_ok: rows.reduce((n, x) => n + x.http_ok, 0),
    http_attempts: rows.reduce((n, x) => n + x.http_attempts, 0),
    weighted_wire_to_udp_ratio: udp ? wire / udp : null,
    over8x_groups: rows.filter((x) => x.over8x).length,
    wire_exceeds8_times_udp_groups: rows.filter(
      (x) => x.wire_exceeds8_times_udp,
    ).length,
    no_native_payload_groups: rows.filter((x) => x.no_native_payload_observed)
      .length,
    over100ms_groups: rows.filter((x) => x.over100ms).length,
    max_client_queue_wait_micros: Math.max(
      ...rows.map((x) => x.max_client_queue_wait_micros),
    ),
    max_client_datagram_age_micros: Math.max(
      ...rows.map((x) => x.max_client_datagram_age_micros),
    ),
    rejected_datagrams: rows.reduce((n, x) => n + x.rejected_datagrams, 0),
    aborted_datagrams: rows.reduce((n, x) => n + x.aborted_datagrams, 0),
  });
}
const logFiles = [
    "client",
    "round-client",
    "round-client-recovered",
    "post-r14",
    "post-r15",
    "post-classical",
    "mature-native/client",
  ]
    .map((p) => "lab/dpi-v2/run/" + p + "/belnet.log")
    .filter((p) => fs.existsSync(p)),
  nativeEvents = [];
for (const file of logFiles) {
  const lines = fs
      .readFileSync(file, "utf8")
      .replace(/\x1b\[[0-9;]*m/g, "")
      .split("\n"),
    closed = [],
    established = [];
  for (const line of lines) {
    let m = line.match(/Session to (\S+) fully closed/);
    if (m) closed.push(m[1]);
    m = line.match(/session with router \[([^\]]+)\] established/);
    if (m) established.push(m[1]);
  }
  nativeEvents.push({
    file,
    sha256: sha(file),
    fully_closed_log_events: closed.length,
    distinct_closed_identities: new Set(closed).size,
    established_log_events: established.length,
    distinct_established_identities: new Set(established).size,
    invalid_attempt: file.includes("/round-client/"),
    mature_baseline: file.includes("/mature-native/"),
  });
}
const nativeSources = new Map(
  [...native, ...rounds].flatMap((row) =>
    (row.states || []).flatMap((state) =>
      (state.observations || []).map((o) => [
        o.session_id,
        { row, observation: o, epoch: state.epoch },
      ]),
    ),
  ),
);
const positiveSourceMismatches = data
  .filter((o) => o.class === "belnet")
  .filter((o) => {
    const s = nativeSources.get(o.session_id);
    return (
      !s ||
      s.row.id !== o.group_id ||
      s.row.split !== o.split ||
      s.epoch !== o.group_id ||
      JSON.stringify(s.observation.events) !== JSON.stringify(o.events)
    );
  })
  .map((o) => o.session_id);
const classical15 = classical.rounds.find((r) => r.round === 15);
const test = forest.adaptive.flow_metrics["split/test"];
const invalid = read(
  "out/dpi-v2/rounds-attempt-1-runtime-mismatch/status.json",
);
const invalidTrials = read(
    "out/dpi-v2/rounds-attempt-1-runtime-mismatch/trials.json",
  ),
  invalidIDs = new Set(
    invalidTrials.flatMap((r) =>
      (r.states || []).flatMap((s) =>
        (s.observations || []).map((o) => o.session_id),
      ),
    ),
  );
const audit = {
  version: 1,
  created_at: new Date().toISOString(),
  passive_only: true,
  input_sha256: before,
  inputs_unchanged: inputs.every((p) => sha(p) === before[p]),
  dataset: {
    deployment_scope:
      "Native TLS epochs retain native process/identity/path state across assigned splits. Zero field-ID collisions is not an independent-user, native-identity or network holdout.",
    positive_scope: positiveScope,
    positive_source_mismatches: positiveSourceMismatches,
    early: summary(data),
    late: summary(late),
    group_split_collisions: collisions,
    duplicate_window_session_ids: duplicateSessions,
    invalid_attempt_session_overlap: data
      .filter((o) => invalidIDs.has(o.session_id))
      .map((o) => o.session_id),
    cross_split_identical_event_traces: repeatedAcrossSplits,
  },
  control_provenance: {
    fresh_local_source_files: localFiles.length,
    local_source_event_mismatches: matchingErrors,
    diagnostic_controls: diag.length,
    diagnostic_session_overlap: data.filter((o) =>
      diagnosticIds.has(o.session_id),
    ).length,
    diagnostic_group_overlap: data.filter((o) =>
      diagnosticGroups.has(o.group_id),
    ).length,
    first_three_uplink_tls_record_lengths: metadata,
    interpretation:
      "Final 72 local and all168 native traces have identical first-three-uplink record lengths58/1208/1189. Earlier108 diagnostic controls had58/1208/1107; excluded from fresh final. Matching this metadata removes one observed shortcut, not every TLS/fixture fingerprint.",
  },
  proofs: {
    summary: ["native", "rounds"].map((run) => {
      const a = nonceChecks.filter((x) => x.run === run);
      return {
        run,
        attempts: a.length,
        successes: a.filter((x) => x.ok).length,
        successful_nonce_missing_service_log: a.filter(
          (x) => x.ok && !x.service_log_matches,
        ).length,
        successful_nonce_size_mismatch: a.filter(
          (x) => x.ok && !x.service_size_match,
        ).length,
        failed_nonce_reached_service: a.filter(
          (x) => !x.ok && x.service_log_matches,
        ).length,
      };
    }),
    duplicate_success_nonces: nonceChecks
      .filter(
        (x, i, a) => x.ok && a.findIndex((y) => y.nonce === x.nonce) !== i,
      )
      .map((x) => x.nonce),
    checks: nonceChecks,
  },
  budgets: {
    definition:
      "Wire is observed TCP ciphertext bytes inclTLS handshakes, excluding TCP/IP/retransmissions. Denominator admitted UDP uplink + decoded delivered UDP downlink. Queue wait/age are CLIENT encoder snapshots, not end-to-end delay or server-queue telemetry.",
    over8x_groups: costs.filter((x) => x.over8x).length,
    finite_ratio_groups: costs.filter((x) => !x.no_native_payload_observed)
      .length,
    wire_exceeds8_times_udp_groups: costs.filter(
      (x) => x.wire_exceeds8_times_udp,
    ).length,
    no_native_payload_groups: costs.filter((x) => x.no_native_payload_observed)
      .length,
    over100ms_groups: costs.filter((x) => x.over100ms).length,
    per_round: roundCosts,
    per_group: costs,
    native_initial_groups: native.map(cost),
    limitations: [
      "Downlink server queue drops are not exposed",
      "Encoder completed means encoded, not delivery ACK",
      "Idle cover and TLS startup can inflate wire/UDP ratio, especially HTTP-failure groups",
      "No claim that old8x/100ms budgets hold",
      "Zero UDP input/output gives undefined ratio and unobserved queue latency, not a cost/latency PASS",
    ],
  },
  native_lifecycle: {
    files: nativeEvents,
    warning:
      "fully_closed entries include pending/path contexts and repeated identities. Do not call event count independent disconnect count; invalid-runtime and mature runs separated.",
  },
  forest: {
    test,
    local_test: forest.adaptive.flow_metrics["test/domain/local-synthetic"],
    real_test: forest.adaptive.flow_metrics["test/domain/real-browser"],
    group_test: forest.adaptive.group_any_block["test/benign"],
    false_positive_budget: 0.05,
    budget_met: test.fpr <= 0.05,
    interpretation:
      "Heldout flow budget FAILED:7/101=6.93%; local7/18, real0/83. Real flows are only6 groups, not83 independent users.",
  },
  classical_early: {
    only_stable_early_scope: true,
    final_round: classical15.metrics,
    interpretation:
      "Flow FPR2/101 but any-block group FPR2/24. Eligible-rule denominator44benign is a separate reported subset; count alleligibleTCPflows101 as main denominator. Optional late calibration excluded from this audit.",
  },
  invalid_runtime: {
    ...invalid,
    excluded_from_main_metrics: true,
    session_overlap_with_final: data.filter((o) => invalidIDs.has(o.session_id))
      .length,
  },
};
fs.writeFileSync(OUT + "/audit.json", JSON.stringify(audit, null, 2) + "\n");
fs.writeFileSync(
  OUT + "/round-costs.json",
  JSON.stringify(roundCosts, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    counts: [data.length, late.length],
    collisions: collisions.length,
    duplicates: duplicateSessions.length,
    nonce: audit.proofs.summary,
    over8x: audit.budgets.over8x_groups,
    over100ms: audit.budgets.over100ms_groups,
    forest_fpr: test.fpr,
    classical_fpr: classical15.metrics.fpr,
    classical_group_fpr: classical15.metrics.group_fpr,
    inputs_unchanged: audit.inputs_unchanged,
  }),
);

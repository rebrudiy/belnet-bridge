"use strict";
// Pure saved-metadata measurement. No Docker, ledger mutation, classifier or fit.
// API: measureGroup(record, outerPCAPBuffer, {wrapperELFSHA,rawSources})
//      buildCost([{record,outerPCAP,rawSources}], {wrapperELFSHA,now})
// CLI: --manifest FILE --out NEW (native-cost-inputs/v1, stageB1, explicit refs).
// Scope: CLIENT UDP input -> successful TCP write, observed through t81000.
// Failed writes are aggregate-only; no per-input failed attribution is invented.
// Nearest-rank quantiles: sorted[ceil(p*N)-1], no interpolation. No samples=>null.
// Canonical udp_stream_metrics.go omits queue_wait_micros only when zero;
// zero is accepted only with valid input/write-start stamps (floor delta0or1us).
// With all three canonical producer sources pinned, queue_wait_micros is the
// Go time.Time.Sub duration (monotonic when both inputs have that reading).
// UnixMicro timestamps are wall-clock labels, not an equality check on that
// duration: https://pkg.go.dev/time#hdr-Monotonic_Clocks
// Manifest example (paths relative to repo root or explicit absolute paths):
// {schema:'native-cost-inputs/v1',stage:'B1',wrapper_elf:{path,sha256},
//  groups:[{group_id,split:'train'|'validation',record:{path,sha256},
//           outer_pcap:{path,sha256}}]}
// Each raw_source ref is retained verbatim for the ledger's independent hashing.
// Authoritative loss counts are null when the input census cannot be verified.
// With a verified census, unresolved accepted inputs are unknown (including
// failures lacking a per-input event), preserving exact conservation. No value
// is silently inferred from absent counters or a failed /state probe.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const ROOT = path.resolve(__dirname, "../.."),
  LIMIT = 256 * 1024 * 1024;
const PRODUCER = {
  metrics_source: {
    path: "udp_stream_metrics.go",
    sha256: "f9d2928eacf46a0aef68d319a78ffddbccd1c82e9d97a5962b75ed96fd810de8",
  },
  forwarding_source: {
    path: "udp_stream.go",
    sha256: "de4214b30c1d671e126c67f8a90b0e0154cab00df773651e6e155c90ffed7233",
  },
  udp_reader_source: {
    path: "udp.go",
    sha256: "a2dc735789e935ceb77698f1a2f90bcfaa7a86851db77e11b1e36a18e420134a",
  },
};
function verifyProducerSources(sources) {
  if (sources === undefined) return false;
  if (!sources || !Object.entries(PRODUCER).every(([key, expected]) => sources[key] === expected.sha256))
    throw Error("canonical_monotonic_producer_source_pins_required");
  return true;
}
const hash = (b) => crypto.createHash("sha256").update(b).digest("hex");
const safe = (n) => Number.isSafeInteger(n) && n >= 0;
const stamp = (n) => Number.isSafeInteger(n) && n > 0;
const hex = (s) => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const add = (set, s) => set.add(s);
const key = (sid, at, bytes) => sid + "|" + at + "|" + bytes;
const sum = (rows, k) => rows.reduce((n, r) => n + r[k], 0);
const fields = [
  "inputs",
  "forwarded",
  "expired",
  "dropped",
  "failed",
  "unknown",
];
const blank = () => Object.fromEntries(fields.map((k) => [k, 0]));
function quantiles(values) {
  const v = [...values].sort((a, b) => a - b);
  return {
    samples: v.length,
    p50_ms: v.length ? v[Math.ceil(0.5 * v.length) - 1] : null,
    p95_ms: v.length ? v[Math.ceil(0.95 * v.length) - 1] : null,
    max_ms: v.length ? v.at(-1) : null,
    quantile: "nearest_rank_sorted_ceil_pN_minus1_no_interpolation",
  };
}
function latency(samples, forwarded, inputs, unknown, census) {
  const q = quantiles(samples);
  let status = "measured";
  if (!census) status = "unknown_unverified_input_census";
  else if (q.samples !== forwarded)
    status = "partial_unknown_forwarded_latency";
  else if (!forwarded)
    status = unknown
      ? "unknown_no_forwarded_observed"
      : inputs
        ? "not_applicable_all_inputs_dropped"
        : "not_applicable_no_inputs";
  return {
    clock: "linux-vm",
    definition: "input_to_write_start",
    status,
    ...q,
    forwarded_without_latency: Math.max(0, forwarded - q.samples),
    scope:
      "Successful CLIENT UDP-to-TCP forwards only; excludes expired/dropped/pending inputs, server reverse path, blocked-write duration and end-to-end delivery",
  };
}
function pcapSummary(raw) {
  const result = {
    sha256: hash(raw),
    file_bytes: raw.length,
    packets: 0,
    captured_packet_bytes: 0,
    original_packet_bytes: 0,
    truncated_packets: 0,
    complete: true,
    errors: [],
    scope:
      "Saved outer PCAP FILE bytes include global/per-record/capture link headers; not literal physical-wire bytes",
  };
  const fail = (s) => {
    result.complete = false;
    result.errors.push(s);
    return result;
  };
  if (raw.length < 24 || raw.length > LIMIT)
    return fail("pcap_missing_or_exceeds256MiB");
  const magic = raw.subarray(0, 4).toString("hex"),
    le = ["d4c3b2a1", "4d3cb2a1"].includes(magic),
    nano = ["4d3cb2a1", "a1b23c4d"].includes(magic);
  if (!le && !["a1b2c3d4", "a1b23c4d"].includes(magic))
    return fail("pcap_magic");
  const u32 = (o) => (le ? raw.readUInt32LE(o) : raw.readUInt32BE(o)),
    u16 = (o) => (le ? raw.readUInt16LE(o) : raw.readUInt16BE(o));
  if (u16(4) !== 2 || u16(6) !== 4 || u32(16) === 0) return fail("pcap_header");
  const snap = u32(16);
  let first = null,
    last = null;
  for (let at = 24; at < raw.length; ) {
    if (at + 16 > raw.length) return fail("pcap_partial_record_header");
    const sec = u32(at),
      fraction = u32(at + 4),
      cap = u32(at + 8),
      original = u32(at + 12);
    at += 16;
    if (
      cap > snap ||
      cap > original ||
      cap > raw.length - at ||
      fraction >= (nano ? 1e9 : 1e6)
    )
      return fail("pcap_partial_or_invalid_record");
    const ns =
      BigInt(sec) * 1000000000n + BigInt(fraction) * (nano ? 1n : 1000n);
    first = first === null || ns < first ? ns : first;
    last = last === null || ns > last ? ns : last;
    result.packets++;
    result.captured_packet_bytes += cap;
    result.original_packet_bytes += original;
    if (cap !== original) result.truncated_packets++;
    at += cap;
  }
  result.first_packet_unix_nanos = first?.toString() ?? null;
  result.last_packet_unix_nanos = last?.toString() ?? null;
  if (result.truncated_packets) fail("pcap_snaplen_truncation");
  return result;
}
function queueWait(event, producerVerified = false) {
  if (
    !stamp(event.input_unix_micros) ||
    !stamp(event.write_started_unix_micros) ||
    !stamp(event.at_unix_micros)
  )
    return null;
  if (producerVerified) {
    // The pinned Go omitempty field is absent exactly when its duration is0.
    if (!Object.hasOwn(event, "queue_wait_micros")) return 0;
    return safe(event.queue_wait_micros) ? event.queue_wait_micros / 1000 : null;
  }
  if (event.write_started_unix_micros < event.input_unix_micros || event.at_unix_micros < event.write_started_unix_micros) return null;
  const delta = event.write_started_unix_micros - event.input_unix_micros;
  if (!Object.hasOwn(event, "queue_wait_micros")) return delta <= 1 ? 0 : null;
  return safe(event.queue_wait_micros) &&
    delta >= event.queue_wait_micros &&
    delta <= event.queue_wait_micros + 1
    ? event.queue_wait_micros / 1000
    : null;
}
function measureClient(
  state,
  history,
  { begin, end, snapshotBegin, snapshotEnd, entry, producerVerified = false },
) {
  const errors = new Set(),
    latencyErrors = new Set();
  let observed = blank();
  const samples = [];
  let wallDurationDisagreements = 0, maxAbsWallDurationDifferenceMicros = 0;
  const bad = (s) => add(errors, s);
  if (!state || typeof state !== "object") state = {};
  if (state.metadata_truncated !== false || state.truncated_batches !== 0)
    bad("client_metadata_truncated_or_unknown");
  if (
    !stamp(state.snapshot_unix_micros) ||
    state.snapshot_unix_micros < end ||
    state.snapshot_unix_micros < snapshotBegin ||
    state.snapshot_unix_micros > snapshotEnd
  )
    bad("client_snapshot_does_not_cover_primary");
  for (const name of [
    "connections",
    "udp_inputs",
    "packet_events",
    "expired_events",
  ])
    if (!Array.isArray(state[name])) bad("missing_" + name);
  const list = (name) =>
    Array.isArray(state[name])
      ? state[name].filter((e) => {
          if (!e || typeof e !== "object") {
            bad("malformed_" + name + "_row");
            return false;
          }
          return true;
        })
      : [];
  const connections = list("connections"),
    inputs = list("udp_inputs"),
    packets = list("packet_events"),
    expired = list("expired_events");
  if (
    connections.some((c) => !hex(c.session_hash)) ||
    inputs.some((c) => !hex(c.session_hash)) ||
    packets.some((c) => !hex(c.session_hash)) ||
    expired.some((c) => !hex(c.session_hash))
  )
    bad("malformed_session_hash");
  if (packets.some((p) => ![1, -1].includes(p.direction)))
    bad("invalid_packet_direction");
  const attached = new Set(connections.map((c) => c.session_hash).filter(hex));
  const inputSIDs = new Set(inputs.map((c) => c.session_hash).filter(hex));
  const sid =
    attached.size === 1
      ? [...attached][0]
      : attached.size === 0 && inputSIDs.size === 1
        ? [...inputSIDs][0]
        : null;
  if (
    attached.size > 1 ||
    (!sid &&
      (inputs.length ||
        packets.some((p) => p.direction === 1) ||
        expired.length))
  )
    bad("ambiguous_or_missing_current_client_SID");
  const same = (r) => sid !== null && r.session_hash === sid;
  const conns = connections.filter(same),
    up = packets.filter((e) => same(e) && e.direction === 1),
    exp = expired.filter(same),
    ins = inputs.filter(same);
  if (
    inputs.some(
      (e) =>
        !same(e) &&
        stamp(e.at_unix_micros) &&
        e.at_unix_micros >= begin &&
        e.at_unix_micros < end,
    )
  )
    bad("excluded_primary_inputs_other_SID");
  const ids = new Set();
  for (const c of conns) {
    if (!safe(c.id) || c.id === 0 || ids.has(c.id))
      bad("invalid_or_duplicate_connection_id");
    ids.add(c.id);
    if (
      !stamp(c.opened_unix_micros) ||
      c.opened_unix_micros > state.snapshot_unix_micros
    )
      bad("missing_or_invalid_connection_open_timestamp");
    for (const k of [
      "up_datagrams",
      "up_bytes",
      "expired_datagrams",
      "expired_bytes",
      "failed_write_datagrams",
      "failed_write_bytes",
      "local_queue_dropped",
    ])
      if (!safe(c[k])) bad("missing_or_invalid_counter_" + k);
  }
  // Earlier sampled identities must remain in an untruncated final history.
  for (const old of history) {
    for (const c of Array.isArray(old?.connections) ? old.connections : []) {
      if (!c) continue;
      if (hex(c.session_hash) && sid && c.session_hash !== sid)
        bad("client_SID_changed_during_group");
      if (
        c.session_hash === sid &&
        !conns.some(
          (n) => n.id === c.id && n.opened_unix_micros === c.opened_unix_micros,
        )
      )
        bad("final_connection_history_missing_earlier_epoch");
    }
  }
  const rows = [],
    pools = new Map();
  for (const e of ins) {
    if (
      !stamp(e.at_unix_micros) ||
      e.at_unix_micros > state.snapshot_unix_micros ||
      !safe(e.bytes) ||
      e.bytes > 65507 ||
      typeof e.accepted !== "boolean"
    ) {
      bad("malformed_input_metadata");
      continue;
    }
    const row = {
      ...e,
      outcome: e.accepted ? "unknown" : "dropped",
      latency: null,
    };
    rows.push(row);
    if (e.accepted) {
      const k = key(sid, e.at_unix_micros, e.bytes);
      if (!pools.has(k)) pools.set(k, { rows: [], next: 0 });
      pools.get(k).rows.push(row);
    }
  }
  const finalInputCounts = new Map();
  for (const r of rows) {
    const k = key(sid, r.at_unix_micros, r.bytes) + "|" + r.accepted;
    finalInputCounts.set(k, (finalInputCounts.get(k) || 0) + 1);
  }
  for (const old of history) {
    if (old?.metadata_truncated === true || old?.truncated_batches > 0)
      bad("earlier_client_metadata_truncated");
    const counts = new Map();
    for (const e of Array.isArray(old?.udp_inputs) ? old.udp_inputs : []) {
      if (!e || e.session_hash !== sid) continue;
      const k = key(sid, e.at_unix_micros, e.bytes) + "|" + e.accepted;
      counts.set(k, (counts.get(k) || 0) + 1);
    }
    for (const [k, n] of counts)
      if (n > (finalInputCounts.get(k) || 0))
        bad("final_input_history_missing_earlier_rows");
  }
  function match(e, outcome) {
    if (
      !stamp(e.input_unix_micros) ||
      !stamp(e.at_unix_micros) ||
      e.at_unix_micros > state.snapshot_unix_micros ||
      e.at_unix_micros < e.input_unix_micros ||
      !safe(e.bytes) ||
      e.bytes > 65507 ||
      !ids.has(e.connection)
    ) {
      bad("malformed_" + outcome + "_event");
      return;
    }
    const p = pools.get(key(sid, e.input_unix_micros, e.bytes));
    if (!p || p.next >= p.rows.length) {
      bad("outcome_without_unconsumed_accepted_input");
      return;
    }
    const row = p.rows[p.next++];
    row.outcome = outcome;
    if (outcome === "forwarded") {
      row.latency = queueWait(e, producerVerified);
      if (producerVerified && row.latency !== null) {
        const wall = e.write_started_unix_micros - e.input_unix_micros;
        const duration = e.queue_wait_micros ?? 0;
        if (wall < duration || wall > duration + 1) {
          wallDurationDisagreements++;
          maxAbsWallDurationDifferenceMicros = Math.max(maxAbsWallDurationDifferenceMicros, Math.abs(wall - duration));
        }
      }
      if (row.latency === null)
        add(latencyErrors, "missing_or_inconsistent_forwarded_queue_latency");
    }
  }
  // Multiset consumption, never unique timestamp or deduplication of equal rows.
  for (const e of up) match(e, "forwarded");
  for (const e of exp) match(e, "expired");
  const countersValid = conns.every((c) =>
    [
      "up_datagrams",
      "up_bytes",
      "expired_datagrams",
      "expired_bytes",
      "failed_write_datagrams",
      "failed_write_bytes",
      "local_queue_dropped",
    ].every((k) => safe(c[k])),
  );
  let failedAggregate = null,
    failedBytes = null,
    droppedCounter = null;
  if (countersValid) {
    failedAggregate = sum(conns, "failed_write_datagrams");
    failedBytes = sum(conns, "failed_write_bytes");
    droppedCounter = Math.max(0, ...conns.map((c) => c.local_queue_dropped));
    if (
      !safe(failedAggregate) ||
      !safe(failedBytes) ||
      !safe(sum(conns, "up_bytes")) ||
      !safe(sum(conns, "expired_bytes"))
    )
      bad("aggregate_counter_overflow");
    if (
      sum(conns, "up_datagrams") !== up.length ||
      sum(conns, "up_bytes") !== sum(up, "bytes") ||
      sum(conns, "expired_datagrams") !== exp.length ||
      sum(conns, "expired_bytes") !== sum(exp, "bytes")
    )
      bad("event_vs_cumulative_counter_mismatch");
    const accepted = rows.filter((r) => r.accepted),
      rejected = rows.length - accepted.length;
    if (
      accepted.length < up.length + exp.length + failedAggregate ||
      sum(accepted, "bytes") <
        sum(up, "bytes") + sum(exp, "bytes") + failedBytes
    )
      bad("input_vs_aggregate_outcome_counter_mismatch");
    // queueDrops is cumulative across reconnects and sampled on writes/expiry;
    // MAX may lag observed false-input rows, so never SUM or require equality.
    if (droppedCounter > rejected)
      bad("drop_counter_exceeds_observed_rejected_inputs");
  }
  const primary = rows.filter(
    (r) => r.at_unix_micros >= begin && r.at_unix_micros < end,
  );
  observed.inputs = primary.length;
  for (const r of primary) {
    observed[r.outcome]++;
    if (r.outcome === "forwarded" && r.latency !== null)
      samples.push(r.latency);
  }
  const complete = errors.size === 0;
  return {
    entry,
    current_client_SID: sid,
    census_complete: complete,
    errors: [...errors],
    latency_errors: [...latencyErrors],
    duration_clock_diagnostics: { source_pinned_monotonic_duration: producerVerified, wall_duration_disagreements: wallDurationDisagreements, max_abs_wall_duration_difference_micros: maxAbsWallDurationDifferenceMicros, scope: "Difference between wall-clock labels and producer duration; not a timing-error bound or correction." },
    observed_input_accounting: observed,
    latency: latency(
      samples,
      observed.forwarded,
      observed.inputs,
      observed.unknown,
      complete,
    ),
    samples,
    aggregates: {
      failed_write_datagrams: failedAggregate,
      failed_write_bytes: failedBytes,
      local_queue_dropped_max: droppedCounter,
      scope:
        "Entire retained selected-client-SID lifetime, across connection epochs. Failed writes have no per-input timestamp attribution; unresolved primary inputs remain unknown.",
    },
    snapshot_unix_micros: state.snapshot_unix_micros ?? null,
    ignored_other_SID_input_rows: inputs.length - ins.length,
  };
}
function applicationBytes(record, begin, end) {
  const attempts = [],
    missing = [];
  let all = 0,
    primary = 0,
    partialPrimary = false;
  for (const a of Array.isArray(record.workloads) ? record.workloads : []) {
    const w = a?.data?.workload;
    const ok =
      w &&
      safe(w.sent_bytes) &&
      safe(w.received_bytes) &&
      safe(w.sent_bytes + w.received_bytes);
    const bytes = ok ? w.sent_bytes + w.received_bytes : null;
    const timed =
      w &&
      stamp(w.started_unix_micros) &&
      stamp(w.finished_unix_micros) &&
      w.finished_unix_micros >= w.started_unix_micros;
    let scope = "unknown_timestamps";
    if (timed)
      scope =
        w.finished_unix_micros <= begin || w.started_unix_micros >= end
          ? "outside_primary"
          : w.started_unix_micros >= begin && w.finished_unix_micros <= end
            ? "wholly_inside_primary"
            : "overlaps_primary_boundary";
    if (ok) all += bytes;
    else missing.push(a?.label || "unnamed");
    if (scope === "wholly_inside_primary" && ok) primary += bytes;
    else if (scope !== "outside_primary") partialPrimary = true;
    attempts.push({
      label: a?.label ?? null,
      client_exit_code: a?.code ?? null,
      bytes,
      scope,
      completed_duration: w?.completed_duration ?? null,
    });
  }
  if (!Array.isArray(record.workloads) || record.workloads.length === 0) {
    missing.push("no_workload_reports");
    partialPrimary = true;
  }
  if (!safe(all)) {
    missing.push("application_byte_sum_overflow");
    all = null;
  }
  if (!safe(primary)) partialPrimary = true;
  return {
    all_attempts: missing.length ? null : all,
    observed_all_attempts_lower_bound: all,
    all_attempts_status: missing.length
      ? "unknown_missing_client_byte_reports"
      : "reported",
    primary: partialPrimary ? null : primary,
    primary_scope_status: partialPrimary
      ? "unknown_no_per_byte_primary_timestamps"
      : "sum_wholly_inside_primary",
    missing_attempts: missing,
    attempts,
    scope:
      "Client application sent_bytes+received_bytes only, all declared recorded attempts; incomplete requests remain included. Primary allocation unavailable for boundary-overlapping/missing-time attempts.",
  };
}
function measureGroup(
  record,
  outerPCAP,
  { wrapperELFSHA, rawSources = [], producerSources } = {},
) {
  if (!hex(wrapperELFSHA)) throw Error("explicit_wrapper_ELF_SHA_required");
  if (!Buffer.isBuffer(outerPCAP))
    throw Error("raw_outer_PCAP_Buffer_required");
  const producerVerified = verifyProducerSources(producerSources);
  const reasons = new Set(),
    begin = record.measurement_start?.unix_micros,
    end = stamp(begin) ? begin + 80000000 : null;
  if (!stamp(begin)) add(reasons, "primary_VM_start_missing");
  const snapshots = Array.isArray(record.snapshots) ? record.snapshots : [];
  const finals = snapshots.filter((s) => s?.label === "t81000"),
    snapshot = finals[0] || {},
    lo = snapshot.clock?.unix_micros,
    hi = snapshot.snapshot_finished?.unix_micros;
  const bounds =
    finals.length === 1 &&
    stamp(lo) &&
    stamp(hi) &&
    hi >= lo &&
    end !== null &&
    lo >= end &&
    Array.isArray(snapshot.clients) &&
    snapshot.clients.length === 2;
  if (!bounds) add(reasons, "final81_client_snapshot_missing_or_incomplete");
  const entries = [0, 1].map((i) =>
    measureClient(
      snapshot.clients?.[i],
      snapshots.filter((s) => s && s !== snapshot).map((s) => s.clients?.[i]),
      {
        begin: stamp(begin) ? begin : 0,
        end: end ?? Number.MAX_SAFE_INTEGER,
        snapshotBegin: stamp(lo) ? lo : 0,
        snapshotEnd: stamp(hi) ? hi : 0,
        entry: i + 1,
        producerVerified,
      },
    ),
  );
  const census = bounds && entries.every((e) => e.census_complete),
    observed = blank();
  for (const e of entries)
    for (const k of fields) observed[k] += e.observed_input_accounting[k];
  const samples = entries.flatMap((e) => e.samples),
    lat = latency(
      samples,
      observed.forwarded,
      observed.inputs,
      observed.unknown,
      census,
    );
  const loss = {
    definition: "bridge_udp_input_to_forward_write",
    status: !census
      ? "INCONCLUSIVE_unverified_input_census"
      : observed.unknown
        ? "INCONCLUSIVE_unresolved_inputs"
        : observed.inputs
          ? "measured"
          : "not_applicable_no_UDP_inputs",
    ...Object.fromEntries(fields.map((k) => [k, census ? observed[k] : null])),
    observed_input_accounting: observed,
    scope:
      "Primary80s CLIENT UDP inputs for selected client SIDs; successful direction1 packet events observed through final81, including grace writes. failed=0 means no individually attributable failed-write event exists; aggregate failures are not assigned to input rows.",
  };
  lat.duration_clock = producerVerified ? "Go_time_Time_Sub_monotonic_source_pinned" : "legacy_UnixMicro_crosscheck_unverified_producer";
  if (!census) add(reasons, "unverified_input_census");
  if (observed.unknown) add(reasons, "unresolved_primary_inputs");
  if (lat.status.startsWith("partial"))
    add(reasons, "forwarded_latency_incomplete");
  const pcap = pcapSummary(outerPCAP),
    capture = (Array.isArray(record.captures) ? record.captures : []).filter(
      (c) => c && /-capture$/.test(c.name),
    );
  let wireComplete = pcap.complete;
  if (
    capture.length !== 1 ||
    capture[0].final_statistics_complete !== true ||
    capture[0].code !== 0 ||
    capture[0].signal ||
    capture[0].capped ||
    capture[0].incomplete ||
    capture[0].forced_cleanup ||
    capture[0].dropped_by_kernel !== 0 ||
    capture[0].captured !== pcap.packets ||
    capture[0].received_by_filter !== pcap.packets ||
    capture[0].bytes !== outerPCAP.length
  )
    wireComplete = false;
  if (!wireComplete) add(reasons, "outer_capture_volume_incomplete");
  const app = applicationBytes(record, stamp(begin) ? begin : 0, end ?? 0);
  if (app.all_attempts === null)
    add(reasons, "application_byte_reports_incomplete");
  const bytes = {
    application: app.all_attempts,
    outer_wire: wireComplete ? outerPCAP.length : null,
    application_scope:
      "all recorded client workload attempts, sent+received reported bytes",
    outer_wire_scope: pcap.scope,
    observed_outer_pcap_file_bytes: outerPCAP.length,
    captured_packet_bytes: pcap.captured_packet_bytes,
    original_packet_bytes: pcap.original_packet_bytes,
    application_primary: app.primary,
  };
  return {
    group_id: record.group?.group_id ?? null,
    wrapper_elf_sha256: wrapperELFSHA,
    status: reasons.size ? "INCONCLUSIVE" : "measured_client_cost",
    measurement_reasons: [...reasons],
    primary_start_unix_micros: stamp(begin) ? begin : null,
    primary_end_unix_micros: end,
    observed_through_snapshot: "t81000",
    loss,
    latency: lat,
    bytes,
    application: app,
    pcap,
    entries: entries.map(({ samples, ...e }) => e),
    raw_sources: rawSources,
    scope:
      "Sampled saved CLIENT-only forwarding cost, not server reverse path, all-input end-to-end latency or E2E loss",
  };
}
function buildCost(
  groups,
  { wrapperELFSHA, now = new Date().toISOString(), producerSources } = {},
) {
  if (
    !hex(wrapperELFSHA) ||
    !Array.isArray(groups) ||
    !groups.length ||
    groups.length > 6
  )
    throw Error("bounded_explicit_native_cost_inputs_required");
  const ids = new Set(),
    out = groups.map((g) => {
      const m = measureGroup(g.record, g.outerPCAP, {
        wrapperELFSHA,
        rawSources: g.rawSources,
        producerSources,
      });
      if (!m.group_id || ids.has(m.group_id))
        throw Error("unique_group_ID_required");
      ids.add(m.group_id);
      return m;
    });
  if (!Number.isFinite(Date.parse(now)) || !now.endsWith("Z"))
    throw Error("UTC_measured_at_required");
  for (const g of groups)
    if (
      g.record.finished_utc &&
      Date.parse(g.record.finished_utc) > Date.parse(now)
    )
      throw Error("measurement_must_follow_saved_run");
  return {
    kind: "native_cost_measurements",
    wrapper_elf_sha256: wrapperELFSHA,
    measured_at: now,
    status: out.every(
      (g) => g.status === "measured_client_cost" && g.loss.inputs > 0,
    )
      ? "measured"
      : "INCONCLUSIVE",
    groups: out,
    measurement_tool_sha256: hash(fs.readFileSync(__filename)),
    producer_semantics: PRODUCER,
    producer_semantics_verified: verifyProducerSources(producerSources),
    scope:
      "CLIENT UDP-to-TCP forwarding only. Unknown/null values are retained and intentionally fail strict complete-cost ledger admission. No E2E loss or ISP claim.",
  };
}
function main(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (
      !["--manifest", "--out"].includes(argv[i]) ||
      args[argv[i]] ||
      !argv[i + 1]
    )
      throw Error("use_explicit_manifest_and_new_out");
    args[argv[i]] = argv[i + 1];
  }
  if (!args["--manifest"] || !args["--out"] || fs.existsSync(args["--out"]))
    throw Error("new_output_and_explicit_manifest_required");
  const manifestRaw = fs.readFileSync(args["--manifest"]),
    m = JSON.parse(manifestRaw);
  if (
    m.schema !== "native-cost-inputs/v1" ||
    m.stage !== "B1" ||
    !Array.isArray(m.groups) ||
    !m.groups.length ||
    m.groups.length > 6 ||
    m.groups.some(
      (g) =>
        !["train", "validation"].includes(g.split) ||
        !g.group_id ||
        /^q-|^b-test-/.test(g.group_id),
    )
  )
    throw Error("only_explicit_development_native_groups_before_reads");
  function readRef(ref) {
    if (
      !ref ||
      !hex(ref.sha256) ||
      typeof ref.path !== "string" ||
      /vault|sealed[-_]|(?:^|[\\/])b-test-/i.test(ref.path)
    )
      throw Error("safe_pinned_reference_required");
    const p = path.resolve(ROOT, ref.path);
    if (fs.statSync(p).size > LIMIT)
      throw Error("INCONCLUSIVE_input_exceeds256MiB");
    const b = fs.readFileSync(p);
    if (hash(b) !== ref.sha256) throw Error("source_SHA_mismatch");
    return b;
  }
  readRef(m.wrapper_elf);
  let producerSources;
  if (m.producer_sources !== undefined) {
    producerSources = {};
    for (const [key, expected] of Object.entries(PRODUCER)) {
      const ref = m.producer_sources[key];
      if (ref?.sha256 !== expected.sha256) throw Error("canonical_monotonic_producer_source_pins_required");
      readRef(ref);
      producerSources[key] = ref.sha256;
    }
  }
  const groups = m.groups.map((g) => {
    const recordRaw = readRef(g.record),
      outerPCAP = readRef(g.outer_pcap),
      record = JSON.parse(recordRaw);
    if (
      record.group?.group_id !== g.group_id ||
      record.group?.split !== g.split ||
      record.group?.class !== "belnet"
    )
      throw Error("native_record_assignment_mismatch");
    return { record, outerPCAP, rawSources: [g.record, g.outer_pcap] };
  });
  const result = buildCost(groups, { wrapperELFSHA: m.wrapper_elf.sha256, producerSources });
  result.producer_source_refs = m.producer_sources ?? null;
  result.input_manifest_sha256 = hash(manifestRaw);
  fs.writeFileSync(args["--out"], JSON.stringify(result, null, 2) + "\n", {
    flag: "wx",
    mode: 0o600,
  });
  return result;
}
if (require.main === module) {
  try {
    const r = main(process.argv.slice(2));
    console.log(
      JSON.stringify({
        kind: r.kind,
        status: r.status,
        groups: r.groups.map((g) => ({
          id: g.group_id,
          status: g.status,
          loss: g.loss,
          latency: g.latency,
        })),
      }),
    );
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
module.exports = {
  measureGroup,
  measureClient,
  buildCost,
  pcapSummary,
  queueWait,
  quantiles,
  applicationBytes,
  main,
};

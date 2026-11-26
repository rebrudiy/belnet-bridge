"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  measureGroup,
  buildCost,
  pcapSummary,
  queueWait,
  quantiles,
  main,
} = require("./round-cost.cjs");

const BEGIN = 1700000000000000,
  END = BEGIN + 80000000;
const SID = "a".repeat(64),
  ELF = "b".repeat(64);
const clone = (x) => structuredClone(x);
function pcap(lengths = [60, 80]) {
  const h = Buffer.alloc(24);
  h.writeUInt32LE(0xa1b2c3d4);
  h.writeUInt16LE(2, 4);
  h.writeUInt16LE(4, 6);
  h.writeUInt32LE(65535, 16);
  h.writeUInt32LE(1, 20);
  return Buffer.concat([
    h,
    ...lengths.map((n, i) => {
      const r = Buffer.alloc(16 + n);
      r.writeUInt32LE(Math.floor(BEGIN / 1e6) + i, 0);
      r.writeUInt32LE(n, 8);
      r.writeUInt32LE(n, 12);
      return r;
    }),
  ]);
}
function input(at = BEGIN + 1000000, bytes = 100, accepted = true) {
  return { at_unix_micros: at, session_hash: SID, bytes, accepted };
}
function forwarded(i, wait = 2500, connection = 1) {
  return {
    at_unix_micros: i.at_unix_micros + wait + 5,
    write_started_unix_micros: i.at_unix_micros + wait,
    input_unix_micros: i.at_unix_micros,
    queue_wait_micros: wait,
    connection,
    session_hash: SID,
    direction: 1,
    bytes: i.bytes,
  };
}
function expired(i, connection = 1) {
  return {
    at_unix_micros: i.at_unix_micros + 200000,
    input_unix_micros: i.at_unix_micros,
    connection,
    session_hash: SID,
    bytes: i.bytes,
    age_micros: 200000,
    max_queue_age_micros: 100000,
    reason: "max_queue_age",
  };
}
function state(inputs = [], up = [], exp = [], extra = {}) {
  return {
    snapshot_unix_micros: END + 1100000,
    metadata_truncated: false,
    truncated_batches: 0,
    connections: [
      {
        id: 1,
        session_hash: SID,
        opened_unix_micros: BEGIN,
        up_datagrams: up.length,
        up_bytes: up.reduce((n, e) => n + e.bytes, 0),
        expired_datagrams: exp.length,
        expired_bytes: exp.reduce((n, e) => n + e.bytes, 0),
        failed_write_datagrams: 0,
        failed_write_bytes: 0,
        local_queue_dropped: inputs.filter((i) => !i.accepted).length,
      },
    ],
    udp_inputs: inputs,
    packet_events: up,
    expired_events: exp,
    ...extra,
  };
}
function fixture(client) {
  const raw = pcap();
  const i = input();
  return {
    raw,
    record: {
      group: { group_id: "r01-rpc", split: "train", class: "belnet" },
      measurement_start: { unix_micros: BEGIN },
      finished_utc: "2024-01-15T00:00:00.000Z",
      snapshots: [
        {
          label: "t81000",
          clock: { unix_micros: END + 1000000 },
          snapshot_finished: { unix_micros: END + 1200000 },
          clients: [client || state([i], [forwarded(i)]), state()],
        },
      ],
      workloads: [
        {
          label: "main",
          code: 0,
          data: {
            workload: {
              sent_bytes: 1000,
              received_bytes: 3000,
              started_unix_micros: BEGIN + 35000000,
              finished_unix_micros: END,
              completed_duration: true,
            },
          },
        },
      ],
      captures: [
        {
          name: "r01-capture",
          code: 0,
          signal: null,
          capped: false,
          incomplete: false,
          forced_cleanup: false,
          final_statistics_complete: true,
          captured: 2,
          received_by_filter: 2,
          dropped_by_kernel: 0,
          bytes: raw.length,
        },
      ],
    },
  };
}
function measure(f) {
  return measureGroup(f.record, f.raw, { wrapperELFSHA: ELF, rawSources: [] });
}
function conserve(m) {
  const l = m.loss;
  assert.equal(
    l.inputs,
    l.forwarded + l.expired + l.dropped + l.failed + l.unknown,
  );
}

test("complete saved client-only costs have exact bytes, known inputs and latency", () => {
  const f = fixture(),
    m = measure(f);
  assert.equal(m.status, "measured_client_cost");
  assert.equal(m.bytes.application, 4000);
  assert.equal(m.bytes.outer_wire, f.raw.length);
  assert.equal(m.bytes.captured_packet_bytes, 140);
  assert.equal(m.loss.inputs, 1);
  assert.equal(m.loss.forwarded, 1);
  assert.equal(m.latency.samples, 1);
  assert.equal(m.latency.p50_ms, 2.5);
  assert.equal(m.latency.status, "measured");
  conserve(m);
  const cost = buildCost([{ record: f.record, outerPCAP: f.raw }], {
    wrapperELFSHA: ELF,
    now: "2027-01-16T00:00:00.000Z",
  });
  assert.equal(cost.kind, "native_cost_measurements");
  assert.equal(cost.status, "measured");
  assert.match(cost.producer_semantics.metrics_source.sha256, /^[0-9a-f]{64}$/);
});

const pinnedProducerSources = () => Object.fromEntries([
  ["metrics_source", "udp_stream_metrics.go"],
  ["forwarding_source", "udp_stream.go"],
  ["udp_reader_source", "udp.go"],
].map(([key, name]) => [key, crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../..", name))).digest("hex")]));

test("source-pinned Go monotonic duration is independent of UnixMicro wall labels", () => {
  const i = input(), event = forwarded(i, 526);
  event.write_started_unix_micros = i.at_unix_micros + 482;
  event.at_unix_micros = i.at_unix_micros + 600;
  assert.equal(queueWait(event), null);
  assert.equal(queueWait(event, true), 0.526);
  const f = fixture(state([i], [event]));
  const m = measureGroup(f.record, f.raw, { wrapperELFSHA: ELF, producerSources: pinnedProducerSources() });
  assert.equal(m.latency.status, "measured");
  assert.equal(m.latency.samples, m.loss.forwarded);
  assert.equal(m.latency.p50_ms, 0.526);
  assert.equal(m.entries[0].duration_clock_diagnostics.wall_duration_disagreements, 1);
});

test("omitted canonical zero duration does not invent a wall-clock duration", () => {
  const i = input(), event = forwarded(i, 0);
  delete event.queue_wait_micros;
  event.write_started_unix_micros = i.at_unix_micros + 9;
  event.at_unix_micros = i.at_unix_micros + 10;
  assert.equal(queueWait(event), null);
  assert.equal(queueWait(event, true), 0);
  assert.equal(queueWait({ ...event, input_unix_micros: undefined }, true), null);
});

test("a changed or incomplete producer cannot enable the monotonic-source interpretation", () => {
  const f = fixture(), pins = pinnedProducerSources();
  assert.throws(() => measureGroup(f.record, f.raw, { wrapperELFSHA: ELF, producerSources: { ...pins, metrics_source: "0".repeat(64) } }), /producer_source_pins_required/);
  assert.throws(() => measureGroup(f.record, f.raw, { wrapperELFSHA: ELF, producerSources: { metrics_source: pins.metrics_source } }), /producer_source_pins_required/);
});
test("multiset collision preserves twins and a rejected input with the identical key", () => {
  const i = input(),
    s = state(
      [i, clone(i), { ...i, accepted: false }],
      [forwarded(i)],
      [expired(i)],
    ),
    m = measure(fixture(s));
  assert.equal(m.loss.inputs, 3);
  assert.equal(m.loss.forwarded, 1);
  assert.equal(m.loss.expired, 1);
  assert.equal(m.loss.dropped, 1);
  assert.equal(m.loss.unknown, 0);
  assert.equal(m.latency.samples, 1);
  conserve(m);
});
test("unconsumed pending inputs stay unknown; failed aggregate cannot attribute an input", () => {
  const i = input(),
    s = state([i]);
  s.connections[0].failed_write_datagrams = 1;
  s.connections[0].failed_write_bytes = i.bytes;
  const m = measure(fixture(s));
  assert.equal(m.status, "INCONCLUSIVE");
  assert.equal(m.loss.inputs, 1);
  assert.equal(m.loss.unknown, 1);
  assert.equal(m.loss.failed, 0);
  assert.equal(m.entries[0].aggregates.failed_write_datagrams, 1);
  assert.equal(m.latency.status, "unknown_no_forwarded_observed");
  conserve(m);
});
test("pending plus successful input has latency only for the successful write", () => {
  const a = input(),
    b = input(BEGIN + 2000000);
  const m = measure(fixture(state([a, b], [forwarded(a)])));
  assert.equal(m.loss.unknown, 1);
  assert.equal(m.loss.forwarded, 1);
  assert.equal(m.latency.samples, 1);
  assert.equal(m.latency.status, "measured");
  assert.equal(m.status, "INCONCLUSIVE");
  conserve(m);
});
test("input before primary end forwarded during grace counts; exact end input does not", () => {
  const a = input(END - 1),
    b = input(END),
    s = state([a, b], [forwarded(a, 500000), forwarded(b, 600000)]),
    m = measure(fixture(s));
  assert.equal(m.loss.inputs, 1);
  assert.equal(m.loss.forwarded, 1);
  assert.equal(m.latency.p95_ms, 500);
  assert.equal(m.status, "measured_client_cost");
  conserve(m);
});
test("all expired and dropped inputs have no invented zero latency", () => {
  const a = input(),
    b = input(BEGIN + 2000000, 20, false),
    m = measure(fixture(state([a, b], [], [expired(a)])));
  assert.equal(m.loss.expired, 1);
  assert.equal(m.loss.dropped, 1);
  assert.equal(m.latency.status, "not_applicable_all_inputs_dropped");
  assert.equal(m.latency.samples, 0);
  assert.equal(m.latency.p50_ms, null);
  conserve(m);
});
test("missing latency does not erase a successful forward or become measured", () => {
  const i = input(),
    e = forwarded(i);
  delete e.queue_wait_micros;
  const m = measure(fixture(state([i], [e])));
  assert.equal(m.loss.forwarded, 1);
  assert.equal(m.loss.unknown, 0);
  assert.equal(m.latency.samples, 0);
  assert.equal(m.latency.status, "partial_unknown_forwarded_latency");
  assert.equal(m.status, "INCONCLUSIVE");
  assert.equal(m.latency.max_ms, null);
});
test("Go omitempty zero wait accepted only with valid zero/floor-rounded stamps", () => {
  const i = input();
  for (const delta of [0, 1]) {
    const e = forwarded(i, delta);
    delete e.queue_wait_micros;
    assert.equal(queueWait(e), 0);
  }
  const e = forwarded(i, 2);
  delete e.queue_wait_micros;
  assert.equal(queueWait(e), null);
  delete e.write_started_unix_micros;
  assert.equal(queueWait(e), null);
  assert.equal(queueWait({ ...forwarded(i), queue_wait_micros: 2501 }), null);
  assert.equal(queueWait({ ...forwarded(i), queue_wait_micros: 2499 }), 2.499);
});
test("truncated or missing counters cannot produce a ledger-compatible zero loss", () => {
  for (const mutate of [
    (s) => (s.metadata_truncated = true),
    (s) => delete s.truncated_batches,
    (s) => delete s.connections[0].up_bytes,
    (s) => s.connections[0].up_datagrams++,
    (s) => (s.expired_events = null),
  ]) {
    const f = fixture();
    mutate(f.record.snapshots[0].clients[0]);
    const m = measure(f);
    assert.equal(m.status, "INCONCLUSIVE");
    for (const k of [
      "inputs",
      "forwarded",
      "expired",
      "dropped",
      "failed",
      "unknown",
    ])
      assert.equal(m.loss[k], null);
    assert.equal(m.loss.observed_input_accounting.forwarded, 1);
  }
});
test("incomplete final snapshot, timestamps and arrays retain unknown rather than zero loss", () => {
  for (const mutate of [
    (r) => (r.snapshots = []),
    (r) => r.snapshots[0].clients.pop(),
    (r) => (r.snapshots[0].clients[0] = { error: "probe failed" }),
    (r) => (r.snapshots[0].clients[0].snapshot_unix_micros = END - 1),
    (r) => (r.snapshots[0].snapshot_finished.unix_micros = END),
    (r) => (r.snapshots[0].clients[0].connections = {}),
    (r) => (r.snapshots[0].clients[0].udp_inputs = [null]),
  ]) {
    const f = fixture();
    mutate(f.record);
    const m = measure(f);
    assert.equal(m.loss.inputs, null);
    assert.equal(m.status, "INCONCLUSIVE");
    assert.equal(m.latency.status, "unknown_unverified_input_census");
  }
});
test("server truncation or missing server state does not change client-only census", () => {
  const f = fixture();
  f.record.snapshots[0].servers = [{ metadata_truncated: true }];
  assert.equal(measure(f).status, "measured_client_cost");
  delete f.record.snapshots[0].servers;
  assert.equal(measure(f).loss.inputs, 1);
});
test("drop cumulative counter uses maximum across reconnect epochs, never a sum", () => {
  const a = input(BEGIN + 1, 50, false),
    b = input(),
    s = state([a, b], [forwarded(b)]);
  s.connections.push({
    ...s.connections[0],
    id: 2,
    opened_unix_micros: BEGIN + 500000,
    up_bytes: 0,
    up_datagrams: 0,
  });
  const m = measure(fixture(s));
  assert.equal(m.status, "measured_client_cost");
  assert.equal(m.loss.dropped, 1);
  assert.equal(m.entries[0].aggregates.local_queue_dropped_max, 1);
  s.connections[0].local_queue_dropped = 2;
  assert.equal(measure(fixture(s)).loss.inputs, null);
});
test("earlier retained input multiplicities and epoch identities cannot disappear", () => {
  for (const mutate of [
    (s) => s.udp_inputs.push(clone(s.udp_inputs[0])),
    (s) => (s.connections[0].id = 2),
  ]) {
    const f = fixture(),
      old = clone(f.record.snapshots[0]);
    old.label = "t79000";
    mutate(old.clients[0]);
    f.record.snapshots.unshift(old);
    assert.equal(measure(f).loss.inputs, null);
  }
});
test("duplicate outcome event and malformed direction are census errors", () => {
  for (const mutate of [
    (s) => s.packet_events.push(clone(s.packet_events[0])),
    (s) => (s.packet_events[0].direction = 0),
    (s) => (s.packet_events[0].connection = 5),
  ]) {
    const f = fixture();
    mutate(f.record.snapshots[0].clients[0]);
    assert.equal(measure(f).loss.inputs, null);
  }
});
test("no UDP is explicitly not applicable, not measured zero E2E loss", () => {
  const f = fixture(state()),
    m = measure(f);
  assert.equal(m.loss.inputs, 0);
  assert.equal(m.loss.status, "not_applicable_no_UDP_inputs");
  assert.equal(m.latency.status, "not_applicable_no_inputs");
  assert.equal(m.latency.p95_ms, null);
  assert.equal(
    buildCost([{ record: f.record, outerPCAP: f.raw }], {
      wrapperELFSHA: ELF,
      now: "2027-01-16T00:00:00.000Z",
    }).status,
    "INCONCLUSIVE",
  );
});
test("nearest rank quantiles and empty samples are exact and do not mutate input", () => {
  const a = [10, 1, 4, 2],
    q = quantiles(a);
  assert.deepEqual(a, [10, 1, 4, 2]);
  assert.equal(q.p50_ms, 2);
  assert.equal(q.p95_ms, 10);
  assert.equal(q.max_ms, 10);
  assert.deepEqual(quantiles([]), {
    samples: 0,
    p50_ms: null,
    p95_ms: null,
    max_ms: null,
    quantile: "nearest_rank_sorted_ceil_pN_minus1_no_interpolation",
  });
});
test("application bytes include incomplete attempts; primary boundary overlap is unknown", () => {
  const f = fixture();
  f.record.workloads.push({
    label: "failed",
    code: 1,
    data: {
      workload: {
        sent_bytes: 30,
        received_bytes: 0,
        started_unix_micros: END - 2,
        finished_unix_micros: END + 2,
        completed_duration: false,
      },
    },
  });
  const m = measure(f);
  assert.equal(m.bytes.application, 4030);
  assert.equal(m.bytes.application_primary, null);
  assert.equal(m.application.attempts[1].scope, "overlaps_primary_boundary");
  delete f.record.workloads[1].data.workload.received_bytes;
  const n = measure(f);
  assert.equal(n.bytes.application, null);
  assert.equal(n.application.observed_all_attempts_lower_bound, 4000);
  assert.equal(n.status, "INCONCLUSIVE");
});
test("raw PCAP size and capture packet counts are separate, mismatch is explicit", () => {
  const f = fixture();
  f.record.captures[0].received_by_filter++;
  let m = measure(f);
  assert.equal(m.bytes.outer_wire, null);
  assert.equal(m.bytes.observed_outer_pcap_file_bytes, f.raw.length);
  assert.equal(m.loss.inputs, 1);
  f.record.captures[0].received_by_filter--;
  f.record.captures[0].final_statistics_complete = false;
  assert.equal(measure(f).bytes.outer_wire, null);
  assert.equal(pcapSummary(f.raw.subarray(0, -1)).complete, false);
  const trunc = Buffer.from(f.raw);
  trunc.writeUInt32LE(99, 36);
  assert.equal(pcapSummary(trunc).complete, false);
});
test("PCAP nanosecond bounds retain int64 precision; empty PCAP has null bounds", () => {
  const raw = pcap([1]);
  raw.writeUInt32LE(0xa1b23c4d, 0);
  raw.writeUInt32LE(999999999, 28);
  const s = pcapSummary(raw);
  assert.equal(s.complete, true);
  assert.equal(
    s.first_packet_unix_nanos,
    (BigInt(Math.floor(BEGIN / 1e6)) * 1000000000n + 999999999n).toString(),
  );
  assert.equal(pcapSummary(pcap([])).first_packet_unix_nanos, null);
});
test("explicit manifest rejects tests before opening any group data and protects existing output", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "round-cost-"));
  try {
    const manifest = path.join(dir, "input.json"),
      out = path.join(dir, "out.json");
    fs.writeFileSync(
      manifest,
      JSON.stringify({
        schema: "native-cost-inputs/v1",
        stage: "B1",
        groups: [
          {
            group_id: "b-test-secret",
            split: "test",
            record: { path: "/must-not-read" },
          },
        ],
      }),
    );
    assert.throws(
      () => main(["--manifest", manifest, "--out", out]),
      /before_reads/,
    );
    assert.equal(fs.existsSync(out), false);
    fs.writeFileSync(out, "untouched");
    assert.throws(
      () => main(["--manifest", manifest, "--out", out]),
      /new_output/,
    );
    assert.equal(fs.readFileSync(out, "utf8"), "untouched");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
test("CLI uses only pinned explicit synthetic refs and emits ledger DTO", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "round-cost-"));
  try {
    const f = fixture(),
      digest = (b) => crypto.createHash("sha256").update(b).digest("hex");
    function ref(name, b) {
      const p = path.join(dir, name);
      fs.writeFileSync(p, b);
      return { path: p, sha256: digest(b) };
    }
    const elf = ref("wrapper.elf", Buffer.from("synthetic ELF reference")),
      record = ref("record.json", Buffer.from(JSON.stringify(f.record))),
      raw = ref("outer.pcap", f.raw),
      manifest = path.join(dir, "manifest.json"),
      out = path.join(dir, "out.json");
    fs.writeFileSync(
      manifest,
      JSON.stringify({
        schema: "native-cost-inputs/v1",
        stage: "B1",
        wrapper_elf: elf,
        groups: [
          { group_id: "r01-rpc", split: "train", record, outer_pcap: raw },
        ],
      }),
    );
    const c = main(["--manifest", manifest, "--out", out]);
    assert.equal(c.kind, "native_cost_measurements");
    assert.equal(c.wrapper_elf_sha256, elf.sha256);
    assert.equal(c.groups[0].raw_sources[0].sha256, record.sha256);
    assert.equal(JSON.parse(fs.readFileSync(out)).groups[0].loss.forwarded, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

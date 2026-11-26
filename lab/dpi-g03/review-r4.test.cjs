"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { guardFreeze, inventoryErrors, timeNS, inspectGroup } = require("./review-r4.cjs");
const at = seconds => new Date(seconds * 1000).toISOString();
const setup = { flow_id: "setup", primary_scope: true, raw_tcp_payload_bytes_including_retransmits: 0, syn_utc: at(203), closed_utc: at(204), first_tls23_utc: null, syn_ack_captured: false };
test("sealed/test and malformed acquisition declarations fail before group I/O", () => {
  assert.throws(() => guardFreeze({ schema: "belnet-g03-collector/v4", stage: "B2" }), /Q_or_B1/);
  const groups = Array.from({ length: 3 }, (_, i) => ({ group_id: "q-" + i, scope: "diagnostic", split: "development" }));
  const f = { schema: "belnet-g03-collector/v4", stage: "Q", groups, test_seeds_commitment: null, files_sha256: { x: "a" } };
  assert.doesNotThrow(() => guardFreeze(f));
  assert.throws(() => guardFreeze({ ...f, groups: groups.map((g, i) => i === 1 ? { ...g, split: "test" } : g) }), /test_or_invalid_scope/);
  assert.throws(() => guardFreeze({ ...f, test_seeds_commitment: {} }), /vault/);
});
test("primary setup-only plus valid grace TLS remains explicit abstention", () => {
  const o = { flows: [setup, { ...setup, flow_id: "grace", primary_scope: false, syn_utc: at(281), closed_utc: null, raw_tcp_payload_bytes_including_retransmits: 26, first_tls23_utc: at(281.002), syn_ack_captured: true }], zero_payload_setup_only: true, group_first_tls23_utc: at(281.002), windows: [], group_windows: [] };
  assert.deepEqual(inventoryErrors(o, 200000000), { errors: [], primary_flows: 1, zero_payload_setup_only: true });
  const hidden = structuredClone(o); hidden.flows[0].primary_scope = false;
  assert.ok(inventoryErrors(hidden, 200000000).errors.includes("flow_scope_lifetime_contradiction"));
  const payload = structuredClone(o); payload.flows[0].raw_tcp_payload_bytes_including_retransmits = 1;
  assert.ok(inventoryErrors(payload, 200000000).errors.includes("primary_payload_without_handshake"));
  const empty = { ...o, flows: [] }; assert.ok(inventoryErrors(empty, 200000000).errors.includes("zero_payload_flag_not_supported_by_primary_inventory"));
});
test("ACK-only and unsampled short primary faults cannot pass inventory checks", () => {
  const o = { flows: [{ ...setup, syn_utc: null }], zero_payload_setup_only: false };
  assert.ok(inventoryErrors(o, 200000000).errors.includes("primary_handshake_inventory_missing"));
  o.flows = [{ ...setup, raw_tcp_payload_bytes_including_retransmits: 100 }];
  assert.ok(inventoryErrors(o, 200000000).errors.includes("primary_payload_without_handshake"));
});
test("nanosecond timestamps preserve primary boundary without millisecond rounding", () => {
  assert.equal(timeNS("1970-01-01T00:04:39.999999999Z"), 279999999999n);
  assert.equal(timeNS("1970-01-01T00:04:40Z"), 280000000000n);
  assert.throws(() => timeNS("not a timestamp"), /invalid_UTC/);
});
test("complete live statistics never substitute for missing or partial final statistics", () => {
  const raw = Buffer.alloc(24); raw.writeUInt32LE(0xa1b2c3d4); raw.writeUInt16LE(2, 4); raw.writeUInt16LE(4, 6); raw.writeUInt32LE(262144, 16); raw.writeUInt32LE(1, 20);
  const live = "tcpdump: 0 packets captured, 0 packets received by filter, 0 packets dropped by kernel\n";
  const c = { name: "x-capture", code: 0, signal: null, capped: false, forced_cleanup: false, incomplete: false, captured: 0, received_by_filter: 0, dropped_by_kernel: 0, bytes: 24, stderr: live, final_statistics_frontier: live.length, final_statistics_complete: true };
  const r = { group: {}, errors: [], captures: [c], measurement_start: { unix_micros: 200000000 } };
  for (const suffix of ["", "0 packets captured\n0 packets received by filter\n"]) {
    c.stderr = live + suffix;
    const result = inspectGroup(r, { flows: [] }, {}, raw, {}, { pcap_cap_bytes: 100 }, "a");
    assert.ok(result.errors.includes("fresh_final_statistics_missing_or_mismatched"));
  }
});

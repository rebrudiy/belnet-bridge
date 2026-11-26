"use strict";
const assert = require("node:assert/strict");
const { extract } = require("./extract.cjs");
const assignment = {
  group_id: "g1",
  family: "test",
  split: "validation",
  variant: "tcp",
};
const constants = {
  logEventTypes: {
    TCP_CONNECT: 1,
    SSL_CONNECT: 2,
    SOCKET_BYTES_SENT: 3,
    SOCKET_BYTES_RECEIVED: 4,
    SOCKET_ALIVE: 5,
  },
};
const raw = (type, time, buf) => ({
  type,
  time: String(time),
  phase: 0,
  source: { id: 7 },
  params: { bytes: buf.toString("base64"), byte_count: buf.length },
});
const header = Buffer.from([22, 3, 3, 0, 1, 1]),
  app = Buffer.from([23, 3, 3, 0, 3, 1, 2, 3]);
function log() {
  return {
    constants,
    events: [
      { type: 1, time: "1000", phase: 2, source: { id: 7 }, params: {} },
      {
        type: 2,
        time: "1001",
        phase: 2,
        source: { id: 7 },
        params: { version: "TLS 1.3", next_proto: "h2" },
      },
      raw(3, 1002, header.subarray(0, 2)),
      raw(3, 1003, header.subarray(2)),
      raw(4, 1004, app.subarray(0, 6)),
      raw(4, 1005, app.subarray(6)),
      raw(3, 1006, app),
      { type: 5, time: "4000", phase: 2, source: { id: 7 } },
    ],
  };
}
const a = extract(log(), assignment, "visit");
assert.equal(a.observations.length, 1);
assert.deepEqual(a.observations[0].events, [
  { at_micros: 0, direction: -1, bytes: 8 },
  { at_micros: 1000, direction: 1, bytes: 8 },
]);
assert.equal(a.observations[0].group_id, "g1");
assert.equal(a.observations[0].split, "validation");
const short = log();
short.events.at(-1).time = "1007";
const b = extract(short, assignment, "short");
assert.equal(b.observations.length, 0);
assert.equal(
  b.flows[0].excluded_reason,
  "prefix_ended_before_2s_or_64_records",
);
const invalid = log();
invalid.events[2] = raw(3, 1002, Buffer.from("GET / HTTP/1.1\r\n"));
assert.equal(extract(invalid, assignment, "plain").observations.length, 0);
const missing = log();
missing.events[2].params.byte_count = 99;
assert.equal(
  extract(missing, assignment, "lost").flows[0].excluded_reason,
  "missing_raw_socket_bytes",
);
console.log("4 meaningful raw TLS extraction checks passed");

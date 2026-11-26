"use strict";
// Passive TCP byte conservation, not a proof of original first-arrival timing.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { inspectPCAP } = require("./review-checkpoint.cjs");
const sha = b => crypto.createHash("sha256").update(b).digest("hex");
function summarizeSegments(segments, maxBytes = 256 * 1024 * 1024) {
  const ordered = [...segments].sort((a, b) => a.offset - b.offset || a.ordinal - b.ordinal);
  const extent = ordered.reduce((n, s) => Math.max(n, s.offset + s.data.length), 0);
  if (extent > maxBytes) throw Error("TCP_sequence_extent_exceeds_capture_bound");
  const bytes = Buffer.alloc(extent), gaps = [];
  let high = 0, unique = 0, overlap = 0, conflicts = 0;
  for (const s of ordered) {
    if (s.offset > high) gaps.push([high, s.offset]);
    const shared = Math.min(s.data.length, Math.max(0, high - s.offset));
    overlap += shared;
    if (shared && !bytes.subarray(s.offset, s.offset + shared).equals(s.data.subarray(0, shared))) conflicts++;
    if (s.data.length > shared) {
      s.data.copy(bytes, s.offset + shared, shared);
      unique += s.data.length - shared;
    }
    high = Math.max(high, s.offset + s.data.length);
  }
  const tls = [];
  let at = 0, tlsIssue = null;
  if (!gaps.length && !conflicts) {
    while (at < bytes.length) {
      if (bytes.length - at < 5) { tlsIssue = "partial_TLS_header"; break; }
      const size = bytes.readUInt16BE(at + 3) + 5;
      if (![20, 21, 22, 23, 24].includes(bytes[at]) || bytes[at + 1] !== 3) { tlsIssue = "unrecognized_TLS_header"; break; }
      if (at + size > bytes.length) { tlsIssue = "partial_TLS_body"; break; }
      tls.push({ type: bytes[at], bytes: size }); at += size;
    }
  } else tlsIssue = "TCP_byte_reassembly_incomplete_or_conflicting";
  return { unique_bytes: unique, overlapping_bytes: overlap, conflicting_segments: conflicts, sequence_gaps: gaps, extent, ciphertext_sha256: sha(bytes), tls_records: tls.length, tls23_records: tls.filter(r => r.type === 23).length, exact26_tls_records: tls.filter(r => r.type === 23 && r.bytes === 26).length, tls_issue: tlsIssue };
}
function parseWire(raw) {
  const capture = inspectPCAP(raw), magic = raw.subarray(0, 4).toString("hex");
  const le = ["d4c3b2a1", "4d3cb2a1"].includes(magic), nanos = ["4d3cb2a1", "a1b23c4d"].includes(magic);
  const u32 = p => le ? raw.readUInt32LE(p) : raw.readUInt32BE(p), link = u32(20);
  if (![1, 113, 276].includes(link)) throw Error("unsupported_PCAP_link_type");
  const streams = new Map(), issues = [], packets = [];
  let at = 24, ordinal = 0;
  while (at < raw.length) {
    const sec = u32(at), sub = u32(at + 4), len = u32(at + 8), p = raw.subarray(at + 16, at + 16 + len);
    at += len + 16; ordinal++;
    const ip = link === 276 ? 20 : link === 113 ? 16 : 14;
    const proto = link === 276 ? 0 : link === 113 ? 14 : 12;
    if (p.length < ip + 20 || p.readUInt16BE(proto) !== 0x0800) { issues.push("non_IPv4_or_short_packet"); continue; }
    const ihl = (p[ip] & 15) * 4, total = p.readUInt16BE(ip + 2), t = ip + ihl;
    if (p[ip + 9] !== 6 || ihl < 20 || t + 20 > p.length || ip + total > p.length || (p.readUInt16BE(ip + 6) & 0x3fff)) { issues.push("unparsed_TCP_or_IP_fragment"); continue; }
    const address = n => [...p.subarray(n, n + 4)].join(".");
    const src = address(ip + 12) + ":" + p.readUInt16BE(t), dst = address(ip + 16) + ":" + p.readUInt16BE(t + 2), key = src + ">" + dst;
    const header = (p[t + 12] >> 4) * 4, count = total - ihl - header, seq = p.readUInt32BE(t + 4), flags = p[t + 13], syn = !!(flags & 2);
    if (header < 20 || count < 0) { issues.push("bad_TCP_header"); continue; }
    if (!streams.has(key)) streams.set(key, { src, dst, base: (seq + (syn ? 1 : 0)) >>> 0, syn: false, segments: [], payload_bytes: 0 });
    const s = streams.get(key); s.syn ||= syn;
    const time = sec * 1e6 + (nanos ? Math.floor(sub / 1000) : sub);
    if (count) {
      const data = p.subarray(t + header, t + header + count);
      s.segments.push({ ordinal, offset: ((seq + (syn ? 1 : 0)) - s.base) >>> 0, data, at_micros: time });
      s.payload_bytes += count;
    }
    packets.push({ ordinal, at_micros: time, src, dst, flags, payload_bytes: count, payload_header_hex: count ? p.subarray(t + header, t + header + Math.min(5, count)).toString("hex") : null });
  }
  return { capture, link_type: link, issues: [...new Set(issues)], streams: [...streams.values()].map(s => ({ src: s.src, dst: s.dst, syn_captured: s.syn, observed_payload_bytes: s.payload_bytes, ...summarizeSegments(s.segments), last_payloads: packets.filter(p => p.src === s.src && p.dst === s.dst && p.payload_bytes).slice(-3) })), packets };
}
function audit(directory) {
  const input_sha256 = {}, read = name => { const p = path.join(directory, name), raw = fs.readFileSync(p); input_sha256[p] = sha(raw); return raw; };
  const record = JSON.parse(read("result.json")), wire = parseWire(read("outer.pcap"));
  const filename = fs.readdirSync(directory).find(n => n.endsWith("-proxy.log"));
  if (!filename) throw Error("proxy_log_missing");
  const events = read(filename).toString().split("\n").filter(Boolean).map(line => JSON.parse(line));
  const expected = new Set(), joins = [];
  for (const event of events.filter(e => e.accepted)) {
    const upKey = event.upstream_local + ">" + event.upstream_remote, downKey = event.upstream_remote + ">" + event.upstream_local;
    expected.add(upKey); expected.add(downKey);
    const up = wire.streams.find(s => s.src + ">" + s.dst === upKey), down = wire.streams.find(s => s.src + ">" + s.dst === downKey);
    const complete = s => !!s && s.syn_captured && !s.sequence_gaps.length && !s.conflicting_segments && !s.tls_issue;
    joins.push({ id: event.id, up_tuple: upKey, down_tuple: downKey, proxy_up_bytes: event.up_bytes, proxy_down_bytes: event.down_bytes, wire_up_unique: up?.unique_bytes ?? null, wire_down_unique: down?.unique_bytes ?? null, up_equal: up?.unique_bytes === event.up_bytes, down_equal: down?.unique_bytes === event.down_bytes, both_streams_structurally_complete: complete(up) && complete(down) });
  }
  const unmatched = wire.streams.filter(s => !expected.has(s.src + ">" + s.dst)).map(s => s.src + ">" + s.dst);
  const outer = record.captures.find(c => /-capture$/.test(c.name));
  const q = record.quiesce?.started_unix_micros;
  const result = { schema: "g03-independent-wire-conservation/v1", group_id: record.group.group_id, input_sha256, auditor_sha256: sha(fs.readFileSync(__filename)), capture: { ...wire.capture, tcpdump_captured: outer?.captured, received_by_filter: outer?.received_by_filter, kernel_drops: outer?.dropped_by_kernel, original_accounting_unknown_retained: outer?.captured !== outer?.received_by_filter }, link_type: wire.link_type, parse_issues: wire.issues, joins, unmatched_streams: unmatched, logged_tuple_payload_conservation: joins.length > 0 && !unmatched.length && !wire.issues.length && joins.every(j => j.up_equal && j.down_equal && j.both_streams_structurally_complete), streams: wire.streams, quiesce: record.quiesce, last_packets: wire.packets.slice(-16), observed_packets_after_quiesce: Number.isSafeInteger(q) ? wire.packets.filter(p => p.at_micros >= q).length : null, limits: ["Exact TCP payload conservation only for logged accepted upstream tuples", "Does not identify which unrecorded packets caused received/captured mismatch", "No proof of original first-arrival timestamps or absence of unseen retransmissions/flows", "Does not upgrade frozen capture UNKNOWN, fit rules or claim DPI bypass"] };
  return result;
}
if (require.main === module) {
  const [dir, output] = process.argv.slice(2); if (!dir || !output) throw Error("usage: node review-wire.cjs GROUP_DIR NEW_OUTPUT");
  const r = audit(dir); fs.writeFileSync(output, JSON.stringify(r, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ group: r.group_id, packets: r.capture.packets, filter: r.capture.received_by_filter, payload_conservation: r.logged_tuple_payload_conservation, joins: r.joins, unmatched: r.unmatched_streams, parse_issues: r.parse_issues }));
}
module.exports = { summarizeSegments, parseWire, audit };

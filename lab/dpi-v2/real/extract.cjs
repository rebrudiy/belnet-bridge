"use strict";
// Parse encrypted TLS outer records only from Chrome raw TCP SOCKET byte events.
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
function extract(log, assignment, visit) {
  const names = Object.fromEntries(
    Object.entries(log.constants.logEventTypes).map(([k, v]) => [v, k]),
  );
  const sockets = new Map();
  let captureEnd = 0,
    quic = {
      packets_sent: 0,
      packets_received: 0,
      bytes_sent: 0,
      bytes_received: 0,
    };
  for (const e of log.events) {
    const t = Number(e.time) * 1000;
    captureEnd = Math.max(captureEnd, t);
    const name = names[e.type] || "";
    if (
      name === "QUIC_SESSION_PACKET_SENT" ||
      name === "QUIC_SESSION_PACKET_RECEIVED"
    ) {
      const key = name.endsWith("SENT") ? "sent" : "received";
      quic["packets_" + key]++;
      quic["bytes_" + key] += e.params?.size || e.params?.packet_length || 0;
    }
    if (!sockets.has(e.source.id))
      sockets.set(e.source.id, {
        id: e.source.id,
        chunks: [],
        connected: false,
        closed: null,
        ssl: null,
      });
    const s = sockets.get(e.source.id);
    if (name === "TCP_CONNECT" && e.phase === 2 && !e.params?.net_error)
      s.connected = true;
    if (name === "SOCKET_ALIVE" && e.phase === 2) s.closed = t;
    if (name === "SSL_CONNECT" && e.phase === 2 && !e.params?.net_error)
      s.ssl = {
        version: e.params?.version,
        protocol: e.params?.next_proto,
        resumed: e.params?.is_resumed,
      };
    if (name === "SOCKET_BYTES_SENT" || name === "SOCKET_BYTES_RECEIVED")
      s.chunks.push({
        t,
        direction: name.endsWith("SENT") ? 1 : -1,
        data: Buffer.from(e.params?.bytes || "", "base64"),
        expected: e.params?.byte_count,
      });
  }
  const observations = [],
    late = [],
    flows = [];
  for (const s of sockets.values()) {
    if (!s.chunks.length) continue;
    const parser = { 1: Buffer.alloc(0), "-1": Buffer.alloc(0) },
      events = [];
    let bad = null,
      handshake = false;
    for (const c of s.chunks) {
      if (c.data.length !== c.expected) {
        bad = "missing_raw_socket_bytes";
        break;
      }
      let buf = Buffer.concat([parser[c.direction], c.data]);
      while (buf.length >= 5) {
        if (buf[0] < 20 || buf[0] > 24 || buf[1] !== 3 || buf[2] > 4) {
          bad = "non_tls_or_misaligned_prefix";
          break;
        }
        const size = buf.readUInt16BE(3) + 5;
        if (buf.length < size) break;
        if (buf[0] === 22 && c.direction === 1) handshake = true;
        if (buf[0] === 23)
          events.push({ absolute: c.t, direction: c.direction, bytes: size });
        buf = buf.subarray(size);
      }
      parser[c.direction] = buf;
      if (bad) break;
    }
    const start = events[0]?.absolute,
      end = s.closed ?? captureEnd;
    const prefix = events
      .filter((e) => e.absolute < start + 2000000)
      .slice(0, 64)
      .map((e) => ({
        at_micros: Math.max(0, e.absolute - start),
        direction: e.direction,
        bytes: e.bytes,
      }));
    const complete = prefix.length === 64 || end >= start + 2000000;
    const reason =
      bad ||
      (!s.connected
        ? "no_successful_tcp_connect"
        : !handshake
          ? "no_client_handshake_prefix"
          : !s.ssl
            ? "no_successful_tls"
            : !events.length
              ? "no_outer_type23_records"
              : !complete
                ? "prefix_ended_before_2s_or_64_records"
                : null);
    const sessionID = visit + "-socket-" + s.id;
    const meta = {
      session_id: sessionID,
      group_id: assignment.group_id,
      split: assignment.split,
      class: "benign",
      profile: "real-" + assignment.family + "-" + assignment.variant,
    };
    const flow = {
      ...meta,
      eligible: !reason,
      excluded_reason: reason,
      tls: s.ssl,
      records: events.length,
      prefix_records: prefix.length,
      lifetime_after_first_application_micros: events.length
        ? Math.max(0, end - start)
        : 0,
      partial_final_record_bytes: parser[1].length + parser[-1].length,
    };
    flows.push(flow);
    if (!reason) {
      observations.push({ ...meta, events: prefix });
      for (const offset of [5000000, 10000000]) {
        if (end < start + offset + 2000000) continue;
        const w = events
          .filter(
            (e) =>
              e.absolute >= start + offset &&
              e.absolute < start + offset + 2000000,
          )
          .slice(0, 64);
        if (!w.length) continue;
        late.push({
          ...meta,
          session_id: sessionID + "-late-" + offset,
          window_offset_micros: offset,
          events: w.map((e) => ({
            at_micros: e.absolute - start - offset,
            direction: e.direction,
            bytes: e.bytes,
          })),
        });
      }
    }
  }
  return { observations, late, flows, quic };
}
function main(root = "out/dpi-v2/real/sessions") {
  const all = [],
    late = [],
    failedObservations = [],
    visits = [];
  if (!fs.existsSync(root)) return;
  for (const visit of fs.readdirSync(root).sort()) {
    const dir = path.join(root, visit),
      netlog = path.join(dir, "private", "netlog.json"),
      assignmentPath = path.join(dir, "assignment.json");
    if (!fs.existsSync(assignmentPath)) continue;
    const assignment = JSON.parse(fs.readFileSync(assignmentPath));
    const summaryPath = path.join(dir, "session.json");
    if (!fs.existsSync(summaryPath) || !fs.existsSync(netlog)) continue;
    let log;
    try {
      log = JSON.parse(fs.readFileSync(netlog));
    } catch {
      continue;
    }
    const result = extract(log, assignment, visit);
    const summary = JSON.parse(fs.readFileSync(summaryPath));
    const protocols = {};
    for (const r of summary.requests)
      if (r.protocol) protocols[r.protocol] = (protocols[r.protocol] || 0) + 1;
    const finalUrl = summary.playback.at(-1)?.url || "";
    const challenge = /\/sorry\/|captcha/i.test(finalUrl);
    const bytes = (r) =>
      Math.max(
        r.encoded_total_bytes || 0,
        r.encoded_stream_bytes || 0,
        r.decoded_bytes || 0,
      );
    const target = new URL(assignment.url);
    const successfulMain = summary.requests.some((r) => {
      try {
        const u = new URL(r.url);
        return (
          r.type === "Document" &&
          r.status === 200 &&
          u.hostname === target.hostname &&
          bytes(r) > 500
        );
      } catch {
        return false;
      }
    });
    const successfulDownload = summary.download
      ? summary.download.status === 200 &&
        summary.download.bytes >=
          Number(target.searchParams.get("bytes") || 500)
      : summary.requests.some((r) => {
          try {
            const u = new URL(r.url);
            return (
              r.status === 200 &&
              u.hostname === target.hostname &&
              u.pathname === target.pathname &&
              bytes(r) > 500
            );
          } catch {
            return false;
          }
        });
    const workloadSuccess =
      assignment.family === "youtube"
        ? summary.actual_video_verified
        : assignment.family === "google"
          ? !challenge && successfulMain
          : assignment.family === "download"
            ? successfulDownload
            : successfulMain;
    const evidence = {
      workload_success: workloadSuccess,
      access_challenge: challenge,
      visit,
      group_id: assignment.group_id,
      family: assignment.family,
      split: assignment.split,
      variant: assignment.variant,
      url: assignment.url,
      started: summary.started,
      finished: summary.finished,
      chrome: summary.chrome.product,
      actual_video_verified: summary.actual_video_verified,
      playback_seconds: summary.video_playback_max_seconds,
      media_bytes: summary.video_media_requests
        .filter((r) => r.status === 200)
        .reduce(
          (n, r) =>
            n +
            Math.max(
              r.encoded_total_bytes || 0,
              r.encoded_stream_bytes || 0,
              r.decoded_bytes || 0,
            ),
          0,
        ),
      requests: summary.requests.length,
      response_protocols: protocols,
      navigation: summary.navigation,
      final_title: summary.playback.at(-1)?.title,
      final_url: summary.playback.at(-1)?.url,
      player_message: summary.playback.at(-1)?.playerMessage,
      video_state: summary.playback.at(-1)?.video,
      download: summary.download,
      request_failures: summary.requests
        .filter((r) => r.failed)
        .map((r) => ({ url: r.url, error: r.failed })),
      eligible_tcp_flows: result.observations.length,
      late_windows: result.late.length,
      quic: result.quic,
      netlog_sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(netlog))
        .digest("hex"),
    };
    fs.writeFileSync(
      path.join(dir, "flows.json"),
      JSON.stringify(result.flows, null, 2) + "\n",
    );
    fs.writeFileSync(
      path.join(dir, "evidence.json"),
      JSON.stringify(evidence, null, 2) + "\n",
    );
    if (workloadSuccess) {
      all.push(...result.observations);
      late.push(...result.late);
    } else failedObservations.push(...result.observations);
    visits.push(evidence);
  }
  fs.writeFileSync(
    "out/dpi-v2/real/observations.json",
    JSON.stringify(all, null, 2) + "\n",
  );
  fs.writeFileSync(
    "out/dpi-v2/real/access-failure-observations.json",
    JSON.stringify(failedObservations, null, 2) + "\n",
  );
  fs.writeFileSync(
    "out/dpi-v2/real/late-observations.json",
    JSON.stringify(late, null, 2) + "\n",
  );
  fs.writeFileSync(
    "out/dpi-v2/real/evidence.json",
    JSON.stringify(
      {
        created_at: new Date().toISOString(),
        visits,
        eligible_tcp_flows: all.length,
        late_windows: late.length,
      },
      null,
      2,
    ) + "\n",
  );
  console.log(
    JSON.stringify({
      visits: visits.length,
      eligible_tcp_flows: all.length,
      late_windows: late.length,
      verified_youtube: visits.filter(
        (v) => v.family === "youtube" && v.actual_video_verified,
      ).length,
    }),
  );
}
module.exports = { extract };
if (require.main === module) main(process.argv[2]);

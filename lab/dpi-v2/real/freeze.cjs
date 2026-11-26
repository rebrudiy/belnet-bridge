"use strict";
const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto"),
  assert = require("node:assert/strict");
const base = "out/dpi-v2/real",
  dest = path.join(base, "frozen-20261119");
if (fs.existsSync(dest))
  throw new Error("Frozen dataset already exists; refusing overwrite");
const plan = require("./plan.json"),
  amend = require("./amendment-001.json"),
  evidence = JSON.parse(fs.readFileSync(path.join(base, "evidence.json"))),
  obs = JSON.parse(fs.readFileSync(path.join(base, "observations.json")));
const planned = [...plan.groups, ...amend.groups].flatMap((g) =>
  g.variants.map((v) => g.group_id + "-" + v),
);
assert.equal(evidence.visits.length, planned.length);
assert.deepEqual(evidence.visits.map((v) => v.visit).sort(), planned.sort());
const groups = new Map(),
  splits = {};
for (const o of obs) {
  assert.equal(o.class, "benign");
  assert.ok(o.events.length > 0 && o.events.length <= 64);
  assert.ok(
    o.events.every(
      (e, i) =>
        e.at_micros >= 0 &&
        e.at_micros < 2000000 &&
        (!i || e.at_micros >= o.events[i - 1].at_micros) &&
        (e.direction === 1 || e.direction === -1) &&
        e.bytes >= 5 &&
        e.bytes <= 65540,
    ),
  );
  assert.ok(!groups.has(o.group_id) || groups.get(o.group_id) === o.split);
  groups.set(o.group_id, o.split);
  splits[o.split] = (splits[o.split] || 0) + 1;
}
const rows = {};
for (const v of evidence.visits) {
  const r = (rows[v.family] ??= {
    attempted_visits: 0,
    successful_visits: 0,
    eligible_primary_tcp_flows: 0,
  });
  r.attempted_visits++;
  if (v.workload_success) {
    r.successful_visits++;
    r.eligible_primary_tcp_flows += v.eligible_tcp_flows;
  }
}
const successfulGroups = {};
for (const [g, s] of groups)
  successfulGroups[s] = (successfulGroups[s] || 0) + 1;
const media = evidence.visits
  .filter((v) => v.family === "youtube" && v.actual_video_verified)
  .map((v) => ({
    visit: v.visit,
    split: v.split,
    transport: v.variant,
    playback_seconds: v.playback_seconds,
    media_response_bytes: v.media_bytes,
    eligible_tcp_flows: v.eligible_tcp_flows,
  }));
const report = `# Реальный обычный трафик: результат\n\n29 визитов, 25 заранее назначенных групп. Успешны 14 визитов / 13 групп.\n239 пригодных TLS/TCP потоков; 29 отдельных поздних окон. Это контроли, не результат обхода DPI.\n\n| Нагрузка | Успешно / попыток | TLS/TCP потоки |\n|---|---:|---:|\n${Object.entries(
  rows,
)
  .map(
    ([k, r]) =>
      `| ${k} | ${r.successful_visits} / ${r.attempted_visits} | ${r.eligible_primary_tcp_flows} |`,
  )
  .join(
    "\n",
  )}\n\nTrain / validation / test: 118 / 57 / 64 потока, но всего 5 / 4 / 4 независимые успешные группы.\nМодель нельзя оценивать так, будто все 239 потоков независимы.\n\nGoogle homepage реально загрузилась во всех трёх split. Семь попыток Google Search\nполучили CAPTCHA/429: их не обходили и не выдавали за успешный поиск.\n\nYouTube: пять настоящих воспроизведений, два разных video ID. Новые validation/test BBB\nчерез TCP: 7.28 / 6.10 секунд playback и 2,401,425 / 1,743,254 media response bytes.\nBBB уже есть в train: это новые сессии, не проверка нового контента.\nЧетыре других видео-визита без playback сохранены как ошибки.\n\nРаботают Wikipedia, RFC8446, Python docs, Go docs; MDN недоступен.\nCloudflare validation download: ровно 524,288 body bytes. RFC9000 test download успешен.\nДве другие Cloudflare нагрузки и Gutenberg недоступны.\n\n181 пригодный TCP поток неуспешных нагрузок сохранён отдельно.\nПилот Google homepage и пилот YouTube исключены из всех split.\n\nQUIC/HTTP3 не оценивался TLS/TCP моделью. Нативный YouTube может передавать media\nчерез HTTP3; TCP observations такого визита включают другие соединения Chrome.\nСырые callbacks и TLS stacks Chrome/Go отличаются; один egress и мало групп\nне дают FPR для провайдера. Начальные окна включают encrypted TLS1.3 handshake.\n\nЗамороженные данные: \`out/dpi-v2/real/frozen-20261119/\`.\nПодробности: \`evidence.json\`, происхождение и SHA-256: \`manifest.json\`.\nСборщик и ограничения: [README](README.md).\n`;
fs.writeFileSync("lab/dpi-v2/real/RESULT.md", report);
fs.mkdirSync(dest);
const sha = (f) =>
    crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex"),
  artifacts = {};
for (const name of [
  "observations.json",
  "late-observations.json",
  "access-failure-observations.json",
  "evidence.json",
]) {
  fs.copyFileSync(path.join(base, name), path.join(dest, name));
  artifacts[name] = {
    sha256: sha(path.join(dest, name)),
    bytes: fs.statSync(path.join(dest, name)).size,
  };
}
const source = {};
for (const name of fs
  .readdirSync("lab/dpi-v2/real")
  .filter((n) => /\.(cjs|json|md)$/.test(n)))
  source[name] = sha(path.join("lab/dpi-v2/real", name));
const manifest = {
  version: 1,
  frozen_at: new Date().toISOString(),
  seeds: [plan.seed, amend.seed],
  attempted_groups: 25,
  attempted_visits: 29,
  successful_visits: evidence.visits.filter((v) => v.workload_success).length,
  successful_groups: groups.size,
  primary_tls_tcp_flows: obs.length,
  split_flows: splits,
  split_successful_groups: successfulGroups,
  families: rows,
  youtube_media_evidence: media,
  observer:
    "Chrome raw TCP SOCKET bytes, client callback time, 1ms resolution; outer TLS23 prefix 2s/64; QUIC separately counted; no PCAP SYN claim",
  source_sha256: source,
  artifacts,
};
fs.writeFileSync(
  path.join(dest, "manifest.json"),
  JSON.stringify(manifest, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    frozen: dest,
    flows: obs.length,
    groups: groups.size,
    splits,
    hash: artifacts["observations.json"].sha256,
  }),
);

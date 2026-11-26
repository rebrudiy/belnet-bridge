"use strict";
const keep = new Set(["q", "v", "hl", "bytes"]);
function safeUrl(value) {
  try {
    const u = new URL(value);
    if (u.protocol === "data:") return "data:[omitted]";
    const params = [...u.searchParams].filter(([k]) => keep.has(k));
    u.search = "";
    if (
      !/googlevideo\.com$/.test(u.hostname) &&
      !u.pathname.includes("/sorry/")
    )
      for (const [k, v] of params) u.searchParams.append(k, v);
    u.hash = "";
    return u.toString();
  } catch {
    return value;
  }
}
function sanitize(summary) {
  const clean = JSON.parse(JSON.stringify(summary));
  clean.url = safeUrl(clean.url);
  for (const key of ["requests", "video_media_requests", "playback"])
    for (const r of clean[key] || []) {
      if (r.url) r.url = safeUrl(r.url);
      if (/^https?:\/\//.test(r.title || "")) r.title = safeUrl(r.title);
    }
  return clean;
}
module.exports = { safeUrl, sanitize };

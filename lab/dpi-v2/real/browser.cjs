"use strict";
// Isolated public browsing only. No existing Chrome profile or user credentials.
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const [url, outDir, seconds = "15", transport = "default"] =
  process.argv.slice(2);
if (!url || !outDir)
  throw new Error("usage: node browser.cjs URL OUTDIR SECONDS default|tcp");
fs.mkdirSync(outDir, { recursive: true });
fs.mkdirSync(path.join(outDir, "private"), { recursive: true });
const profile = path.join(outDir, "private", "profile");
const args = [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-sync",
  "--disable-extensions",
  "--password-store=basic",
  "--use-mock-keychain",
  "--mute-audio",
  "--autoplay-policy=no-user-gesture-required",
  "--remote-debugging-port=0",
  "--user-data-dir=" + profile,
  "--log-net-log=" + path.join(outDir, "private", "netlog.json"),
  "--net-log-capture-mode=Everything",
];
if (transport === "tcp") args.push("--disable-quic");
const browser = cp.spawn(
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  args,
  { stdio: ["ignore", "ignore", "pipe"] },
);
process.once("SIGTERM", () => {
  browser.kill("SIGTERM");
  fs.writeFileSync(
    path.join(outDir, "failure.json"),
    JSON.stringify({ error: "acquisition terminated before completion" }) +
      "\n",
  );
  process.exit(1);
});
let stderr = "";
browser.stderr.on("data", (x) => (stderr += x.toString()));
const pending = new Map();
let nextId = 0;
let socket;
const records = new Map(),
  errors = [],
  playback = [];
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("CDP timeout " + method));
    }, 12000);
    pending.set(id, { resolve, reject, timer });
    socket.send(
      JSON.stringify({
        id,
        method,
        params,
        ...(sessionId ? { sessionId } : {}),
      }),
    );
  });
}
async function main() {
  const devtools = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 120 && !fs.existsSync(devtools); i++) await sleep(100);
  if (!fs.existsSync(devtools))
    throw new Error("Chrome DevTools did not start: " + stderr.slice(-1000));
  const [port, wsPath] = fs.readFileSync(devtools, "utf8").trim().split("\n");
  socket = new WebSocket("ws://127.0.0.1:" + port + wsPath);
  await new Promise((res, rej) => {
    socket.addEventListener("open", res, { once: true });
    socket.addEventListener("error", rej, { once: true });
  });
  socket.addEventListener("message", (event) => {
    const m = JSON.parse(event.data);
    if (m.id) {
      const p = pending.get(m.id);
      if (!p) return;
      clearTimeout(p.timer);
      pending.delete(m.id);
      if (m.error) p.reject(new Error(JSON.stringify(m.error)));
      else p.resolve(m.result);
      return;
    }
    const p = m.params || {};
    if (m.method === "Network.requestWillBeSent")
      records.set(p.requestId, {
        id: p.requestId,
        url: p.request.url,
        method: p.request.method,
        type: p.type,
        timestamp: p.timestamp,
      });
    if (m.method === "Network.responseReceived") {
      const old = records.get(p.requestId) || { id: p.requestId };
      const r = p.response;
      Object.assign(old, {
        url: r.url,
        status: r.status,
        mime: r.mimeType,
        protocol: r.protocol,
        fromDiskCache: r.fromDiskCache,
        remoteIPAddress: r.remoteIPAddress,
      });
      records.set(p.requestId, old);
    }
    if (m.method === "Network.dataReceived") {
      const r = records.get(p.requestId) || { id: p.requestId };
      r.decoded_bytes = (r.decoded_bytes || 0) + p.dataLength;
      r.encoded_stream_bytes =
        (r.encoded_stream_bytes || 0) + p.encodedDataLength;
      records.set(p.requestId, r);
    }
    if (m.method === "Network.loadingFinished") {
      const r = records.get(p.requestId) || { id: p.requestId };
      r.finished = true;
      r.encoded_total_bytes = p.encodedDataLength;
      records.set(p.requestId, r);
    }
    if (m.method === "Network.loadingFailed") {
      const r = records.get(p.requestId) || { id: p.requestId };
      r.failed = p.errorText;
      r.canceled = p.canceled;
      records.set(p.requestId, r);
    }
  });
  const version = await command("Browser.getVersion");
  const target = await command("Target.createTarget", { url: "about:blank" });
  const attached = await command("Target.attachToTarget", {
    targetId: target.targetId,
    flatten: true,
  });
  const sid = attached.sessionId;
  for (const method of ["Network.enable", "Page.enable", "Runtime.enable"])
    await command(method, {}, sid);
  await command("Network.setCacheDisabled", { cacheDisabled: true }, sid);
  const started = new Date().toISOString();
  const binaryDownload = /speed\.cloudflare\.com\/__down/.test(url);
  const navigation = await command(
    "Page.navigate",
    {
      url: binaryDownload ? "https://speed.cloudflare.com/cdn-cgi/trace" : url,
    },
    sid,
  );
  let download = null;
  if (binaryDownload) {
    await sleep(1800);
    download = await command(
      "Runtime.evaluate",
      {
        expression:
          "fetch(" +
          JSON.stringify(url) +
          ").then(async r=>({status:r.status,bytes:(await r.arrayBuffer()).byteLength})).catch(e=>({error:String(e)}))",
        awaitPromise: true,
        returnByValue: true,
      },
      sid,
    )
      .then((r) => r.result.value)
      .catch((e) => ({ error: String(e) }));
  }
  const deadline = Date.now() + Number(seconds) * 1000;
  let consentChecked = false;
  while (Date.now() < deadline) {
    await sleep(1000);
    if (!consentChecked) {
      consentChecked = true;
      await command(
        "Runtime.evaluate",
        {
          expression: `(()=>{const b=[...document.querySelectorAll('button')].find(x=>/^(Reject all|Reject All|Отклонить все)$/i.test(x.innerText.trim()));if(b){b.click();return 'normal-consent-reject';}return null;})()`,
          returnByValue: true,
        },
        sid,
      ).catch((e) => errors.push(String(e)));
    }
    const result = await command(
      "Runtime.evaluate",
      {
        expression: `(()=>{const v=document.querySelector('video');if(v){v.muted=true;v.play().catch(()=>{});}return {url:location.href,title:document.title,video:v?{currentTime:v.currentTime,duration:Number.isFinite(v.duration)?v.duration:null,paused:v.paused,readyState:v.readyState,error:v.error?{code:v.error.code,message:v.error.message}:null}:null,playerMessage:document.querySelector('.ytp-error-content-wrap')?.innerText||null};})()`,
        returnByValue: true,
      },
      sid,
    ).catch((e) => {
      errors.push(String(e));
      return null;
    });
    if (result)
      playback.push({
        time: new Date().toISOString(),
        ...(result.result.value || {}),
      });
  }
  const summary = {
    url,
    started,
    finished: new Date().toISOString(),
    transport,
    chrome: version,
    navigation,
    download,
    requests: [...records.values()],
    playback,
    errors,
  };
  summary.video_media_requests = summary.requests.filter(
    (r) =>
      (/googlevideo\.com/.test(r.url || "") ||
        /^video\//.test(r.mime || "") ||
        /^audio\//.test(r.mime || "")) &&
      (r.encoded_total_bytes || 0) +
        (r.encoded_stream_bytes || 0) +
        (r.decoded_bytes || 0) >
        0,
  );
  summary.video_playback_max_seconds = Math.max(
    0,
    ...playback.map((x) => x.video?.currentTime || 0),
  );
  summary.actual_video_verified =
    summary.video_playback_max_seconds >= 2 &&
    summary.video_media_requests.some(
      (r) =>
        r.status === 200 &&
        Math.max(
          r.encoded_total_bytes || 0,
          r.encoded_stream_bytes || 0,
          r.decoded_bytes || 0,
        ) >= 10000,
    );
  fs.writeFileSync(
    path.join(outDir, "private", "session-raw.json"),
    JSON.stringify(summary, null, 2) + "\n",
  );
  const sanitized = require("./sanitize.cjs").sanitize(summary);
  fs.writeFileSync(
    path.join(outDir, "session.json"),
    JSON.stringify(sanitized, null, 2) + "\n",
  );
  await command("Browser.close").catch(() => {});
  await Promise.race([
    new Promise((r) => browser.once("exit", r)),
    sleep(8000),
  ]);
  if (browser.exitCode === null) browser.kill("SIGTERM");
  fs.writeFileSync(path.join(outDir, "private", "chrome-stderr.log"), stderr);
  console.log(
    JSON.stringify({
      outDir,
      requests: records.size,
      video: summary.actual_video_verified,
      maxTime: summary.video_playback_max_seconds,
      mediaRequests: summary.video_media_requests.length,
      errors: summary.errors,
    }),
  );
}
main().catch(async (e) => {
  fs.writeFileSync(
    path.join(outDir, "failure.json"),
    JSON.stringify({ error: String(e), stderr: stderr.slice(-2000) }, null, 2),
  );
  browser.kill("SIGTERM");
  console.error(String(e));
  process.exitCode = 1;
});

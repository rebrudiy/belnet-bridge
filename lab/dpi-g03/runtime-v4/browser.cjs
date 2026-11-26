"use strict";
// Isolated public browsing only. No existing Chrome profile or user credentials.
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Fixed-width correlation values only; no group/class/split identifier goes on wire.
function parseWarmupNonces(text, mainNonce) {
  if (text === undefined) return null;
  let values;try{values=JSON.parse(text);}catch{throw Error("G03_WARMUP_NONCES must be a JSON array3");}
  if(!Array.isArray(values)||values.length!==3||values.some(x=>typeof x!=="string"||!/^[0-9a-f]{64}$/.test(x))||new Set(values).size!==3||values.includes(mainNonce))throw Error("G03_WARMUP_NONCES needs3 unique64hex values distinct from main nonce");
  return values;
}
function matchedWarmupURL(mainURL, step, frozenNonce) {
  if (!Number.isInteger(step) || step < 0 || step > 2) throw Error("warmup step must be0..2");
  const u = new URL(mainURL), seed = u.searchParams.get("seed"), nonce = u.searchParams.get("nonce");
  if (!/^[0-9a-f]{16}$/.test(seed || "") || !/^[0-9a-f]{64}$/.test(nonce || "")) throw Error("matched workload needs fixed16hex seed and64hex nonce");
  const maximum=(1n<<48n)-1n, mainSeed=BigInt("0x"+seed);
  if(mainSeed<1n||mainSeed>maximum)throw Error("main seed outside bounded workload range");
  const value=((mainSeed-1n+9000n+BigInt(step))%maximum)+1n;
  const derivedNonce = ((BigInt("0x" + nonce) + BigInt(step + 1)) % (1n << 256n)).toString(16).padStart(64, "0");
  const nextNonce=frozenNonce===undefined?derivedNonce:frozenNonce;
  if(typeof nextNonce!=="string"||!/^[0-9a-f]{64}$/.test(nextNonce)||nextNonce===nonce)throw Error("invalid frozen warmup nonce");
  u.searchParams.set("family", "rpc");
  u.searchParams.set("duration_ms", "1000");
  u.searchParams.set("seed", value.toString(16).padStart(16, "0"));
  u.searchParams.set("nonce", nextNonce);
  return { url: u.toString(), seed: Number(value), nonce: nextNonce, step, nonce_source:frozenNonce===undefined?"derived":"frozen_env" };
}
function matchedInitialURL(mainURL, frozenNonce) {
  const u=new URL(mainURL),mainNonce=u.searchParams.get("nonce"),seed=u.searchParams.get("seed");
  // Validate canonical main parameters and the later warmup seed bounds too.
  matchedWarmupURL(mainURL,2);
  const nonce=frozenNonce===undefined?((BigInt("0x"+mainNonce)+4n)%(1n<<256n)).toString(16).padStart(64,"0"):frozenNonce;
  if(typeof nonce!=="string"||!/^[0-9a-f]{64}$/.test(nonce)||nonce===mainNonce)throw Error("invalid initial nonce");
  const initialSeed=((BigInt("0x"+seed)-1n+8999n)%((1n<<48n)-1n))+1n;
  u.searchParams.set("family","rpc");u.searchParams.set("duration_ms","1000");u.searchParams.set("seed",initialSeed.toString(16).padStart(16,"0"));u.searchParams.set("nonce",nonce);
  return {url:u.toString(),seed:Number(initialSeed),nonce,nonce_source:frozenNonce===undefined?"derived":"frozen_env",scheduled_ms:0};
}
async function awaitStartBarrier(file, {timeoutMS=120000, pollMS=50, isAlive=()=>true}={}) {
  const deadline = Date.now()+timeoutMS;
  while (true) {
    if (!isAlive()) throw Error("Chrome exited before start barrier");
    if (fs.existsSync(file)) {
      if (!fs.statSync(file).isFile()) throw Error("start barrier must be a regular file");
      return {file:path.resolve(file),observed_host_utc:new Date().toISOString(),clock_scope:"host_lifecycle_only_not_VM"};
    }
    if (Date.now()>=deadline) throw Error("G03 start barrier timed out");
    await sleep(Math.min(pollMS,Math.max(1,deadline-Date.now())));
  }
}
function childAlreadyExited(child) {
  return (child.exitCode!==null&&child.exitCode!==undefined)||(child.signalCode!==null&&child.signalCode!==undefined);
}
function clearCDPPending(pending) {
  if(!pending)return 0;
  const count=pending.size;
  for(const entry of pending.values()){
    clearTimeout(entry.timer);
    if(entry.reject){const e=new Error("CDP canceled during browser teardown");e.code="G03_TEARDOWN";entry.reject(e);}
  }
  pending.clear();return count;
}
// Owns one deadline for all graceful/TERM/KILL stages. Browser.close ACK is not
// awaited: Chrome can exit before sending it. Exit listeners precede the send.
async function closeBrowserBounded({browser,socket,pending,requestClose,budgetMS=3000,graceMS=750,termMS=750}) {
  const start=performance.now(),deadline=start+budgetMS;
  const result={started_host_utc:new Date().toISOString(),clock_scope:"host_lifecycle_only_not_VM",signals:[],errors:[],already_exited:childAlreadyExited(browser)};
  let exited=result.already_exited,resolveExit;
  const exit=new Promise(resolve=>{resolveExit=resolve;});
  const onExit=()=>{exited=true;resolveExit(true);};
  browser.once("exit",onExit);browser.once("close",onExit);
  if(childAlreadyExited(browser))onExit();
  const wait=async milliseconds=>{
    if(exited||childAlreadyExited(browser)){onExit();return true;}
    const remaining=Math.max(0,Math.min(milliseconds,deadline-performance.now()));
    if(remaining===0)return false;
    let timer;
    try{return await Promise.race([exit,new Promise(resolve=>{timer=setTimeout(()=>resolve(false),remaining);})]);}
    finally{clearTimeout(timer);}
  };
  const kill=signal=>{if(exited||childAlreadyExited(browser)){onExit();return;}result.signals.push(signal);try{browser.kill(signal);}catch(e){result.errors.push(String(e));}};
  try{
    if(!exited&&requestClose){
      try{const ack=requestClose();if(ack&&typeof ack.catch==="function")ack.catch(e=>result.errors.push(String(e)));}
      catch(e){result.errors.push(String(e));}
    }
    if(!await wait(graceMS)){kill("SIGTERM");if(!await wait(termMS)){kill("SIGKILL");await wait(deadline-performance.now());}}
  }finally{
    browser.removeListener("exit",onExit);browser.removeListener("close",onExit);
    result.pending_cdp_canceled=clearCDPPending(pending);
    try{if(socket){socket.close();if(typeof socket.terminate==="function")socket.terminate();}}catch(e){result.errors.push(String(e));}
  }
  result.exited=exited||childAlreadyExited(browser);
  result.result=result.exited?"exited":"bounded_timeout";
  result.exit_code=browser.exitCode??null;result.signal_code=browser.signalCode??null;
  result.finished_host_utc=new Date().toISOString();result.elapsed_ms=performance.now()-start;
  return result;
}
// Completion means BOTH raw and sanitized session files were already written.
// Teardown interruption never overwrites them or creates an acquisition failure.
function recordInterruption(outDir,completed,signal) {
  const result={signal,stage:completed?"teardown":"acquisition",acquisition_complete:completed,summary_preserved:completed,at_host_utc:new Date().toISOString(),clock_scope:"host_lifecycle_only_not_VM"};
  if(!completed)result.error="acquisition terminated before completion";
  const filename=completed?"teardown-interruption.json":"failure.json";
  fs.writeFileSync(path.join(outDir,filename),JSON.stringify(result,null,2)+"\n");
  return {filename,exitCode:completed?0:1,result};
}
module.exports={matchedWarmupURL,matchedInitialURL,parseWarmupNonces,awaitStartBarrier,childAlreadyExited,clearCDPPending,closeBrowserBounded,recordInterruption};
if (require.main===module) {
const [url, outDir, seconds = "80", proxy, pins = "", scenario = "public"] =
  process.argv.slice(2);
if (!url || !outDir || !proxy || !['public','matched','long'].includes(scenario))
  throw new Error("usage: node browser.cjs URL OUTDIR SECONDS LOOPBACK_CONNECT_PROXY PINS public|matched|long");
const barrierFile=process.env.G03_START_FILE ? path.resolve(process.env.G03_START_FILE) : null;
if (barrierFile && fs.existsSync(barrierFile)) throw Error("Refusing stale preexisting G03_START_FILE");
if (!Number.isFinite(Number(seconds)) || Number(seconds)<1 || Number(seconds)>80) throw Error("bounded1..80second timeline required");
const frozenWarmupNonces=scenario==='matched'?parseWarmupNonces(process.env.G03_WARMUP_NONCES,new URL(url).searchParams.get('nonce')):null;
const warmupPlan=scenario==='matched'?[0,1,2].map(i=>matchedWarmupURL(url,i,frozenWarmupNonces?.[i])):[];
if(scenario==='matched'&&barrierFile&&!process.env.G03_INITIAL_NONCE)throw Error("Collector matched session requires G03_INITIAL_NONCE");
const initialPlan=scenario==='matched'?matchedInitialURL(url,process.env.G03_INITIAL_NONCE):null;
if(initialPlan&&warmupPlan.some(x=>x.nonce===initialPlan.nonce))throw Error("Initial nonce must be distinct from every warmup nonce");
fs.mkdirSync(outDir, { recursive: true });
fs.mkdirSync(path.join(outDir, "private"), { recursive: true });
const profile = path.join(outDir, "private", "profile");
const launch=require('../controls/browser-flags.cjs').chromeArgs({profile,artifactRoot:outDir,proxy,labSPKI:pins?pins.split(','):[]});
const args = [...launch.args,
  "--remote-debugging-port=0",
  "--log-net-log=" + path.join(outDir, "private", "netlog.json"),
  "--net-log-capture-mode=Everything",
  "about:blank",
];
const transport='explicit-tcp-connect';
const browser = cp.spawn(
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  args,
  { stdio: ["ignore", "ignore", "pipe"] },
);
let stderr = "";
browser.stderr.on("data", (x) => (stderr += x.toString()));
const pending = new Map();
let nextId = 0;
let socket;
const records = new Map(),
  errors = [],
  playback = [];
let acquisitionComplete=false,acquisitionInterrupted=false,teardownPromise,helperFinishing=false;
function teardown(){
  if(!teardownPromise)teardownPromise=closeBrowserBounded({browser,socket,pending,requestClose:()=>{
    // No pending ACK/timer: Chrome may have already exited when this completes.
    if(socket?.readyState===1)socket.send(JSON.stringify({id:++nextId,method:"Browser.close"}));
  }}).then(result=>{fs.writeFileSync(path.join(outDir,"teardown.json"),JSON.stringify(result,null,2)+"\n");return result;});
  return teardownPromise;
}
function finishHelper(code,output){
  if(helperFinishing)return;helperFinishing=true;
  fs.writeFileSync(path.join(outDir,"private","chrome-stderr.log"),stderr);
  // Closing an undici WebSocket can retain its handshake timer. Once evidence
  // and bounded teardown are saved, explicitly end this acquisition helper.
  const fallback=setTimeout(()=>process.exit(code),100);fallback.unref();
  process.stdout.write(JSON.stringify(output)+"\n",()=>process.exit(code));
}
process.once("SIGTERM",()=>{
  if(!acquisitionComplete)acquisitionInterrupted=true;
  const disposition=recordInterruption(outDir,acquisitionComplete,"SIGTERM");
  teardown().then(result=>finishHelper(disposition.exitCode,{outDir,interruption:disposition.result,teardown:result})).catch(e=>finishHelper(disposition.exitCode,{outDir,interruption:disposition.result,teardown_error:String(e)}));
});
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
  const ready={ready:true,host_ready_utc:new Date().toISOString(),clock_scope:"host_lifecycle_only_not_VM",pid:process.pid,chrome_pid:browser.pid,scenario,transport,stage:"CDP about:blank ready; no workload navigation",start_file:barrierFile,chrome:version};
  fs.writeFileSync(path.join(outDir,"ready.json"),JSON.stringify(ready,null,2)+"\n");
  const barrier=barrierFile?await awaitStartBarrier(barrierFile,{isAlive:()=>browser.exitCode===null}):null;
  const timelineStartedMS=Date.now();
  const started = new Date(timelineStartedMS).toISOString();
  const deadline=timelineStartedMS+Number(seconds)*1000;
  const warmups=[];
  const initial=initialPlan?{...initialPlan,started_host_utc:new Date().toISOString(),actual_offset_ms:Date.now()-timelineStartedMS,samples:[]}:null;
  const binaryDownload = /speed\.cloudflare\.com\/__down/.test(url);
  const navigation = await command(
    "Page.navigate",
    {
      url: initial?initial.url:binaryDownload ? "https://speed.cloudflare.com/cdn-cgi/trace" : url,
    },
    sid,
  );
  if(initial)initial.navigation=navigation;
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
  const createdAt=timelineStartedMS;let warmupStep=0,mainStarted=scenario!=='matched';
  let consentChecked = false;
  while (Date.now() < deadline) {
    if(acquisitionInterrupted)throw Error("acquisition interrupted before completion");
    await sleep(1000);
    if(scenario==='matched'&&!mainStarted){
      const elapsed=Date.now()-createdAt;
      if(warmupStep<3&&elapsed>=[5000,15000,25000][warmupStep]){
        const w={...warmupPlan[warmupStep],scheduled_ms:[5000,15000,25000][warmupStep],started_host_utc:new Date().toISOString(),actual_offset_ms:elapsed,samples:[]};
        warmups.push(w);
        try{w.navigation=await command('Page.navigate',{url:w.url},sid);}catch(e){w.error=String(e);errors.push(String(e));}
        warmupStep++;
      }
      if(elapsed>=35000){await command('Page.navigate',{url},sid);mainStarted=true;}
    }
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
        expression: `(()=>{const v=document.querySelector('video');if(v){v.muted=true;v.play().catch(()=>{});}return {url:location.href,title:document.title,bench:window.__bench||null,video:v?{currentTime:v.currentTime,duration:Number.isFinite(v.duration)?v.duration:null,paused:v.paused,readyState:v.readyState,error:v.error?{code:v.error.code,message:v.error.message}:null}:null,playerMessage:document.querySelector('.ytp-error-content-wrap')?.innerText||null};})()`,
        returnByValue: true,
      },
      sid,
    ).catch((e) => {
      errors.push(String(e));
      return null;
    });
    if (result) {
      const sample={time:new Date().toISOString(),...(result.result.value||{})};
      playback.push(sample);
      let observedNonce=null;try{observedNonce=new URL(sample.url).searchParams.get('nonce');}catch{}
      const warmup=warmups.find(w=>w.nonce===observedNonce);
      if(warmup)warmup.samples.push(sample);
      if(initial&&initial.nonce===observedNonce)initial.samples.push(sample);
    }
  }
  if(acquisitionInterrupted)throw Error("acquisition interrupted before completion");
  const summary = {
    url,
    started,
    finished: new Date().toISOString(),
    transport,scenario,launch_scope:launch.scope,
    chrome: version,
    ready,barrier,initial,warmups,main_started:mainStarted,timeline_seconds:Number(seconds),timeline_clock_scope:"host_lifecycle_only_not_VM; collector supplies prelaunch VM anchor",
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
    summary.video_playback_max_seconds >= 5 &&
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
  acquisitionComplete=true;
  const teardownResult=await teardown();
  finishHelper(0,{
    outDir,requests:records.size,video:summary.actual_video_verified,
    maxTime:summary.video_playback_max_seconds,mediaRequests:summary.video_media_requests.length,
    errors:summary.errors,teardown:teardownResult,
  });
}
main().catch(async e=>{
  fs.writeFileSync(path.join(outDir,acquisitionComplete?"teardown-error.json":"failure.json"),JSON.stringify({error:String(e),acquisition_complete:acquisitionComplete,stage:acquisitionComplete?"teardown":"acquisition",stderr:stderr.slice(-2000)},null,2)+"\n");
  let result;try{result=await teardown();}catch(closeError){result={error:String(closeError)};}
  finishHelper(acquisitionComplete?0:1,{outDir,error:String(e),acquisition_complete:acquisitionComplete,teardown:result});
});
}

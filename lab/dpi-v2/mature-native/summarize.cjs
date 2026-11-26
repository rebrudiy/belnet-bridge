"use strict";
const fs = require("fs"),
  cp = require("child_process"),
  crypto = require("crypto"),
  path = require("path");
const out = "out/dpi-v2/mature-native",
  trials = JSON.parse(fs.readFileSync(out + "/trials.json")),
  parsed = JSON.parse(fs.readFileSync(out + "/reassembled.json")),
  observations = JSON.parse(fs.readFileSync(out + "/observations.json")),
  plan = JSON.parse(fs.readFileSync(out + "/preregistration.json"));
const log = fs
  .readFileSync(out + "/belnet.log", "utf8")
  .replace(/\x1b\[[0-9;]*m/g, "");
const events = [];
for (const line of log.split("\n")) {
  let m = line.match(/session with router \[([^\]]+)\] established/);
  if (m) events.push({ kind: "established", identity: m[1], line });
  m = line.match(/Session to (\S+) fully closed/);
  if (m) events.push({ kind: "fully_closed_log_event", identity: m[1], line });
}
const established = new Set(
  events.filter((e) => e.kind === "established").map((e) => e.identity),
);
fs.writeFileSync(
  out + "/native-events.json",
  JSON.stringify(
    {
      events,
      established_identities: [...established],
      warning:
        "Repeated fully-closed log events can refer to pending/path contexts; event count is not a count of independent disconnects.",
    },
    null,
    2,
  ) + "\n",
);
const records = trials.map((t) => {
  const p = parsed.pcaps.find((p) => path.basename(p.pcap, ".pcap") === t.id);
  return {
    id: t.id,
    split: t.split,
    proof_ok: t.proofs.filter((p) => p.ok).length,
    proof_attempts: t.proofs.length,
    errors: t.proofs.filter((p) => !p.ok).map((p) => p.error),
    eligible_tls_flows: p.flows.filter((f) => f.eligible).length,
    ineligible_flows: p.flows
      .filter((f) => !f.eligible)
      .map((f) => ({ tuple: f.tuple, reasons: f.exclusion_reasons })),
    pcap_bytes: fs.statSync(p.pcap).size,
    started: t.started,
    finished: t.finished,
  };
});
const hashes = {};
function hashFile(file) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(file))
    .digest("hex");
}
for (const file of fs
  .readdirSync(out)
  .filter(
    (n) => /\.(json|jsonl|pcap|log|txt)$/.test(n) && n !== "manifest.json",
  ))
  hashes[file] = hashFile(out + "/" + file);
const binaries = {
  sing_box: {
    path: "out/dpi-v2/mature/bin/sing-box",
    sha256: hashFile("out/dpi-v2/mature/bin/sing-box"),
  },
  native_belnet: {
    path: "/usr/local/bin/belnet in " + plan.runtime_image,
    sha256: "53bdf1d5712a058e43a2e03a3c22bfccc2d96234d4354258b1fffd186329b881",
    source:
      "480aafb3, TESTNET=ON and documented one-line queue-wakeup patch inherited from lab runtime",
  },
  nonce_probe: {
    path: "lab/evolution/evo-probe-linux",
    sha256: hashFile("lab/evolution/evo-probe-linux"),
  },
};
const manifest = {
  version: 1,
  created_at: new Date().toISOString(),
  real_native_belnet: true,
  echo_used: false,
  public_internet_decoy: false,
  censorship_enforcement: false,
  client_ip: plan.client_ip,
  runtime_image: plan.runtime_image,
  binaries,
  groups: records,
  proof_successes: trials.reduce(
    (n, t) => n + t.proofs.filter((p) => p.ok).length,
    0,
  ),
  proof_attempts: trials.reduce((n, t) => n + t.proofs.length, 0),
  eligible_tls_observations: observations.length,
  split_observations: observations.reduce(
    (m, o) => ((m[o.split] = (m[o.split] || 0) + 1), m),
    {},
  ),
  limitations: [
    "Six sequential groups share native identity/state: assigned splits are labels, not independent clients",
    "PCAP completion timing differs from client callback timing; exploratory scoring only",
    "Cold first-node stream can predate capture startup; any incomplete prefix excluded",
    "UDP source identity before/after was not measured as a paired cold-vs-restart comparison; prior isolated baseline independently observed source-port changes",
    "Failing or empty groups are application failures/ineligible, not DPI evasion",
    "No externally realistic decoy or commercial DPI tested",
  ],
  native_event_counts: {
    established_log_events: events.filter((e) => e.kind === "established")
      .length,
    fully_closed_log_events: events.filter(
      (e) => e.kind === "fully_closed_log_event",
    ).length,
    distinct_established_identities: established.size,
  },
  cleanup: {
    removed_only_prefix: "bb-dpi-mature-",
    existing_native_entries_and_main_client_untouched: true,
  },
  source_sha256: Object.fromEntries(
    fs
      .readdirSync("lab/dpi-v2/mature-native")
      .filter((name) => /\.(cjs|sh|md)$/.test(name))
      .map((name) => [name, hashFile("lab/dpi-v2/mature-native/" + name)]),
  ),
  private_config_sha256: Object.fromEntries(
    fs
      .readdirSync(out + "/private")
      .filter((name) => name.endsWith(".json"))
      .map((name) => [name, hashFile(out + "/private/" + name)]),
  ),
  artifacts_sha256: hashes,
};
fs.writeFileSync(
  out + "/manifest.json",
  JSON.stringify(manifest, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    groups: records.map((r) => ({
      id: r.id,
      ok: r.proof_ok,
      eligible: r.eligible_tls_flows,
    })),
    proofs: [manifest.proof_successes, manifest.proof_attempts],
    native_events: manifest.native_event_counts,
  }),
);

"use strict";
// Reuse the existing reassembler with a port selector and empty-capture handling.
const fs = require("fs"),
  cp = require("child_process"),
  crypto = require("crypto"),
  path = require("path");
const out = "out/dpi-v2/mature-native";
const sourcePath = "lab/crosscheck/offline/reassemble.py";
const original = fs.readFileSync(sourcePath, "utf8");
for (const marker of [
  "if 443 not in (sport, dport):",
  "direction = 1 if dport == 443 else -1",
])
  if (!original.includes(marker))
    throw Error("Parser changed; manual review required");
const adapted = original
  .replace("if 443 not in (sport, dport):", "if 19443 not in (sport, dport):")
  .replace(
    "direction = 1 if dport == 443 else -1",
    "direction = 1 if dport == 19443 else -1",
  )
  .replaceAll("tcp443", "tcp19443")
  .replace(
    "def utc(micros):\n    return",
    "def utc(micros):\n    if micros is None:\n        return None\n    return",
  );
const parsed = cp.spawnSync(
  "python3",
  ["-c", adapted, out, path.join(out, "reassembled.json")],
  { encoding: "utf8", timeout: 30000, maxBuffer: 16 * 1024 * 1024 },
);
if (parsed.status !== 0) throw Error(parsed.stderr);
console.log(parsed.stdout.trim());
const plan = JSON.parse(
    fs.readFileSync(path.join(out, "preregistration.json")),
  ),
  data = JSON.parse(fs.readFileSync(path.join(out, "reassembled.json"))),
  all = [];
for (const capture of data.pcaps) {
  const group = plan.groups.find(
    (g) => g.id === path.basename(capture.pcap, ".pcap"),
  );
  if (!group) throw Error("Unplanned PCAP");
  const eligible = new Set(
    capture.flows.filter((f) => f.eligible).map((f) => f.session_id),
  );
  for (const o of capture.observations)
    if (eligible.has(o.session_id))
      all.push({
        ...o,
        group_id: group.id,
        split: group.split,
        class: "belnet",
        profile: "mature-native-REALITY-pcap",
      });
}
fs.writeFileSync(
  path.join(out, "observations.json"),
  JSON.stringify(all, null, 2) + "\n",
);
const hash = (x) => crypto.createHash("sha256").update(x).digest("hex");
fs.writeFileSync(
  path.join(out, "parser-provenance.json"),
  JSON.stringify(
    {
      source: sourcePath,
      source_sha256: hash(original),
      adapted_sha256: hash(adapted),
      adaptation:
        "TCP server-port selector 443→19443 and counter label; utc(None) returns null for empty final PCAP; original captures unchanged",
      observer:
        "PCAP record-completion time; not client socket callback; report separately from training observations",
      eligible_observations: all.length,
    },
    null,
    2,
  ) + "\n",
);
console.log(
  JSON.stringify({
    eligible: all.length,
    groups: new Set(all.map((o) => o.group_id)).size,
    splits: all.reduce((m, o) => ((m[o.split] = (m[o.split] || 0) + 1), m), {}),
  }),
);

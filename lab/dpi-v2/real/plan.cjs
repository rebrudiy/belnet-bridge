"use strict";
const fs = require("fs");
const families = {
  google: [
    ["https://www.google.com/search?q=how+do+solar+panels+work", "train"],
    ["https://www.google.com/search?q=history+of+public+libraries", "train"],
    ["https://www.google.com/search?q=beginner+bread+recipe", "train"],
    ["https://www.google.com/search?q=weather+cloud+types", "validation"],
    ["https://www.google.com/search?q=architecture+of+ancient+bridges", "test"],
  ],
  youtube: [
    ["https://www.youtube.com/watch?v=aqz-KE-bpKQ&autoplay=1&hl=en", "train"],
    ["https://www.youtube.com/watch?v=M7lc1UVf-VE&autoplay=1&hl=en", "train"],
    ["https://www.youtube.com/watch?v=ysz5S6PUM-U&autoplay=1&hl=en", "train"],
    [
      "https://www.youtube.com/watch?v=jNQXAC9IVRw&autoplay=1&hl=en",
      "validation",
    ],
    ["https://www.youtube.com/watch?v=dQw4w9WgXc&autoplay=1&hl=en", "test"],
  ],
  docs: [
    ["https://developer.mozilla.org/en-US/docs/Web/HTTP", "train"],
    ["https://en.wikipedia.org/wiki/Internet", "train"],
    ["https://www.rfc-editor.org/rfc/rfc8446", "train"],
    ["https://docs.python.org/3/tutorial/", "validation"],
    ["https://go.dev/doc/effective_go", "test"],
  ],
  download: [
    ["https://speed.cloudflare.com/__down?bytes=1048576", "train"],
    ["https://speed.cloudflare.com/__down?bytes=2097152", "train"],
    ["https://www.gutenberg.org/cache/epub/1342/pg1342.txt", "train"],
    ["https://speed.cloudflare.com/__down?bytes=524288", "validation"],
    ["https://www.rfc-editor.org/rfc/rfc9000.txt", "test"],
  ],
};
const groups = Object.entries(families).flatMap(([family, rows]) =>
  rows.map(([url, split], i) => ({
    group_id: `real-${family}-${i + 1}`,
    family,
    url,
    split,
    variants:
      (family === "youtube" && [0, 3].includes(i)) ||
      (family === "google" && [0, 3].includes(i))
        ? ["default", "tcp"]
        : ["default"],
    seconds: family === "youtube" ? 30 : 15,
  })),
);
const plan = {
  version: 1,
  seed: 202611190731,
  preregistered_at: new Date().toISOString(),
  scope:
    "20 fresh whole-session groups; 24 fresh browser visits; pilot excluded; entire group and its transport variants stay in same split",
  observer:
    "Chrome raw SOCKET NetLog client callback timestamp, encrypted outer TLS records only; QUIC separately reported, not fed to TCP detector",
  splits: { train: 12, validation: 4, test: 4 },
  pilot_excluded: true,
  groups,
};
if (fs.existsSync("lab/dpi-v2/real/plan.json"))
  throw Error("Preregistration already exists");
fs.writeFileSync(
  "lab/dpi-v2/real/plan.json",
  JSON.stringify(plan, null, 2) + "\n",
);

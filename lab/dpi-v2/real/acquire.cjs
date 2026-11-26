"use strict";
const fs = require("fs"),
  path = require("path"),
  cp = require("child_process");
const plan = require(
  process.argv[2] ? path.resolve(process.argv[2]) : "./plan.json",
);
const root = "out/dpi-v2/real/sessions";
fs.mkdirSync(root, { recursive: true });
const jobs = plan.groups.flatMap((g) =>
  g.variants.map((variant) => ({ ...g, variant })),
);
let cursor = 0;
async function worker() {
  while (cursor < jobs.length) {
    const j = jobs[cursor++],
      dir = path.join(root, j.group_id + "-" + j.variant);
    if (
      fs.existsSync(path.join(dir, "session.json")) ||
      fs.existsSync(path.join(dir, "failure.json"))
    )
      continue;
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "assignment.json"),
      JSON.stringify({ ...j, seed: plan.seed }, null, 2) + "\n",
    );
    await new Promise((resolve) => {
      const p = cp.spawn(
        process.execPath,
        [
          path.join(__dirname, "browser.cjs"),
          j.url,
          dir,
          String(j.seconds),
          j.variant,
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let output = "";
      p.stdout.on("data", (b) => (output += b));
      p.stderr.on("data", (b) => (output += b));
      const timer = setTimeout(() => p.kill("SIGTERM"), 110000);
      p.on("exit", (code) => {
        clearTimeout(timer);
        fs.writeFileSync(
          path.join(dir, "process.json"),
          JSON.stringify({ exit_code: code, output }, null, 2) + "\n",
        );
        console.log(j.group_id, j.variant, code, output.trim());
        resolve();
      });
    });
  }
}
Promise.all([worker(), worker()]).catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

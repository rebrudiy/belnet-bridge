"use strict";
const fs = require("fs"),
  cp = require("child_process"),
  path = require("path");
const { exec } = require("./common.cjs");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
class Capture {
  constructor({
    name,
    network,
    image,
    directory,
    file,
    iface = "eth0",
    filter,
    maxBytes,
    binary = true,
    spawn = cp.spawn,
    run = exec,
    timeouts = {},
  }) {
    this.run = run;
    this.timeouts = {
      ready: 5000,
      stop: 5000,
      close: 2000,
      kill: 3000,
      final: 1000,
      ...timeouts,
    };
    this.name = name;
    this.maxBytes = maxBytes;
    this.bytes = 0;
    this.capped = false;
    this.forced = false;
    this.stderr = "";
    this.started = new Date().toISOString();
    this.fd = fs.openSync(path.join(directory, file), "wx");
    let readyResolve, readyReject, closedResolve;
    this.readiness = new Promise((resolve, reject) => {
      readyResolve = resolve;
      readyReject = reject;
    });
    this.readiness.catch(() => {});
    this.closed = new Promise((resolve) => (closedResolve = resolve));
    this.finalize = (code, signal) => {
      if (this.finished) return;
      if (this.fd !== null) {
        fs.closeSync(this.fd);
        this.fd = null;
      }
      this.finished = new Date().toISOString();
      this.code = code;
      this.signal = signal;
      if (!this.listening)
        readyReject(
          Error("Capture closed before listening banner: " + this.stderr),
        );
      closedResolve();
    };
    const command = [
      "run",
      "--name",
      name,
      "--network",
      "container:" + network,
      "--entrypoint",
      "tcpdump",
      image,
      "-U",
      "-n",
      "-i",
      iface,
      ...(binary ? ["-w", "-"] : ["-tt", "-l"]),
      ...filter,
    ];
    this.child = spawn("docker", command, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.child.stdout.on("data", (b) => {
      if (this.fd === null) return;
      const left = maxBytes - this.bytes;
      if (left > 0) {
        const n = Math.min(left, b.length);
        try {
          fs.writeSync(this.fd, b.subarray(0, n));
        } catch (error) {
          this.stderr += "\nCapture file write failed: " + error.message;
          this.forced = true;
          this.stop().catch(() => {});
          return;
        }
        this.bytes += n;
      }
      if (this.bytes >= maxBytes && !this.capped) {
        this.capped = true;
        this.stop().catch((e) => (this.stderr += "\ncap stop: " + e.message));
      }
    });
    this.child.stderr.on("data", (b) => {
      this.stderr += b;
      if (!this.listening && /listening on /.test(this.stderr)) {
        this.listening = true;
        this.listening_at = new Date().toISOString();
        readyResolve();
      }
    });
    this.child.once("close", (code, signal) => this.finalize(code, signal));
    this.child.once("error", (e) => {
      this.stderr += "\n" + e.message;
      this.finalize(-1, "spawn_error");
    });
  }
  async ready() {
    let timer;
    try {
      await Promise.race([
        this.readiness,
        new Promise((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                Error("No tcpdump listening banner within5s: " + this.stderr),
              ),
            this.timeouts.ready,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  async stop() {
    if (!this.stopping)
      this.stopping = (async () => {
        await this.run(
          ["docker", "stop", "--signal", "SIGINT", "--time", "2", this.name],
          { allowFailure: true, timeout: this.timeouts.stop },
        ).catch((error) => {
          this.stderr += "\nGraceful capture stop failed: " + error.message;
        });
        let closed = await Promise.race([
          this.closed.then(() => true),
          wait(this.timeouts.close).then(() => false),
        ]);
        if (!closed) {
          this.forced = true;
          await this.run(["docker", "kill", this.name], {
            allowFailure: true,
            timeout: this.timeouts.kill,
          }).catch((error) => {
            this.stderr += "\nForced capture stop failed: " + error.message;
          });
          this.child.kill("SIGKILL");
          closed = await Promise.race([
            this.closed.then(() => true),
            wait(this.timeouts.final).then(() => false),
          ]);
          if (!closed) this.finalize(-1, "capture_cleanup_timeout");
        }
      })();
    return this.stopping;
  }
  result() {
    const number = (pattern) => {
      const m = this.stderr.match(pattern);
      return m ? Number(m[1]) : null;
    };
    const dropped = number(/(\d+) packets dropped by kernel/);
    return {
      name: this.name,
      started: this.started,
      listening_at: this.listening_at,
      finished: this.finished,
      bytes: this.bytes,
      cap_bytes: this.maxBytes,
      capped: this.capped,
      forced_cleanup: this.forced,
      code: this.code,
      signal: this.signal,
      captured: number(/(\d+) packets captured/),
      received_by_filter: number(/(\d+) packets received by filter/),
      dropped_by_kernel: dropped,
      stderr: this.stderr,
      incomplete:
        this.capped || this.forced || this.code !== 0 || dropped !== 0,
    };
  }
}
module.exports = { Capture };

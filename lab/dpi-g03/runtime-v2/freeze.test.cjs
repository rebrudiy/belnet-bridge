"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("fs"),
  os = require("os"),
  path = require("path");
const { validate } = require("./freeze.cjs");
function rejected(value, pattern) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "g03-freeze-"));
  try {
    const f = path.join(dir, "freeze.json");
    fs.writeFileSync(f, JSON.stringify(value));
    assert.throws(() => validate(f), pattern);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
test("B2 cannot start acquisition before final policy gate exists", () =>
  rejected(
    { schema: "belnet-g03-collector/v2", stage: "B2" },
    /Invalid collector/,
  ));
test("B1 cannot smuggle sealed-test assignments", () =>
  rejected(
    {
      schema: "belnet-g03-collector/v2",
      stage: "B1",
      groups: [{ split: "test" }],
    },
    /train\/validation only/,
  ));
test("paired source workloads cannot share a cohort", () =>
  rejected(
    {
      schema: "belnet-g03-collector/v2",
      stage: "B1",
      groups: [
        {
          group_id: "a",
          scope: "primary",
          split: "train",
          source_workload_id: "same",
        },
        {
          group_id: "b",
          scope: "primary",
          split: "train",
          source_workload_id: "same",
        },
      ],
      batches: [["a", "b"]],
    },
    /mixed-cohort/,
  ));

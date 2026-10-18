import test from "node:test";
import assert from "node:assert/strict";
import { createReaSourceAnalyzer } from "./rea-source.mjs";

test("real REA JavaScript service produces evidence for original authorized source", async () => {
  const analyze = await createReaSourceAnalyzer();
  const files = [
    {
      path: "package.json",
      content: JSON.stringify({
        name: "nova-original-fixture",
        version: "1.0.0",
        main: "index.js",
        type: "module",
      }),
    },
    {
      path: "index.js",
      content:
        "export function score(points,bonus) { return points + bonus; }\n",
    },
  ];
  const report = await analyze(files, new AbortController().signal);
  assert.equal(
    report.engine,
    "nova-source-inventory+rea-javascript",
    JSON.stringify(report.limitations),
  );
  assert.ok(report.reaEvidence && typeof report.reaEvidence === "object");
  assert.equal(report.inventory.length, 2);
  assert.ok(report.inventory.every((file) => file.sha256.length === 64));
  console.log(
    JSON.stringify({
      realReaJavaScript: true,
      files: report.inventory.length,
      evidencePreserved: true,
      targetExecuted: false,
    }),
  );
});

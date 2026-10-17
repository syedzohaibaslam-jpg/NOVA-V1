import test from "node:test";
import assert from "node:assert/strict";
import { createAnalysisServer } from "./server.mjs";

const token = "a".repeat(40);
async function fixture(t, options = {}) {
  const events = [];
  const server = createAnalysisServer({
    credentials: [{ token, organizationId: "org" }],
    audit: (e) => events.push(e),
    ...options,
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(
    () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(r);
      }),
  );
  const call = async (
    tool,
    input = {},
    context = { organizationId: "org", projectId: "project" },
    secret = token,
  ) => {
    const response = await fetch(
      `http://127.0.0.1:${server.address().port}/tools/execute`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${secret}` },
        body: JSON.stringify({ tool, input, context }),
      },
    );
    return { status: response.status, data: await response.json() };
  };
  return { call, events };
}
const source = {
  authorization: "authorized",
  files: [
    {
      path: "package.json",
      content: '{"name":"demo","scripts":{"test":"node --test"}}',
    },
    { path: "src/main.java", content: "class Main {}" },
  ],
};

test("authenticated discovery, real structured analysis, evidence and tenant isolation", async (t) => {
  const { call, events } = await fixture(t);
  assert.equal(
    (await call("analysis.discover", {}, undefined, "wrong")).status,
    401,
  );
  assert.equal(
    (
      await call(
        "analysis.discover",
        {},
        { organizationId: "other", projectId: "project" },
      )
    ).status,
    403,
  );
  assert.equal(
    (await call("analysis.discover")).data.engines.find(
      (e) => e.id === "rea-jadx",
    ).available,
    false,
  );
  const started = await call("analysis.start", source);
  assert.equal(started.status, 202);
  const jobId = started.data.id;
  assert.equal(
    (
      await call(
        "analysis.status",
        { jobId },
        { organizationId: "org", projectId: "other" },
      )
    ).status,
    404,
  );
  let job;
  for (let i = 0; i < 20; i++) {
    job = (await call("analysis.status", { jobId })).data;
    if (job.status === "completed") break;
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.equal(job.status, "completed");
  assert.equal(job.result.coverage.examinedFiles, 2);
  assert.equal(job.result.inventory[0].sha256.length, 64);
  assert.equal(job.result.findings[0].confidence, "observed");
  assert.ok(events.some((e) => e.action === "analysis.completed"));
  assert.ok(!JSON.stringify(events).includes(token));
});
test("reject unauthorized source, path traversal, duplicates, secrets and oversized files", async (t) => {
  const { call } = await fixture(t);
  for (const input of [
    { ...source, authorization: "no" },
    ...["../x", "/x", "a\\b", ".env", "a/.env.local"].map((path) => ({
      authorization: "authorized",
      files: [{ path, content: "x" }],
    })),
    { ...source, files: [source.files[0], source.files[0]] },
    { ...source, files: [{ path: "x", content: "x".repeat(128001) }] },
  ])
    assert.equal((await call("analysis.start", input)).status, 400);
});
test("cancellation and timeout discard late results and keep capacity until cleanup", async (t) => {
  const analyze = (_files, signal) =>
    new Promise((resolve, reject) => {
      signal.addEventListener(
        "abort",
        () => setTimeout(() => reject(Error("cancelled")), 30),
        { once: true },
      );
    });
  const { call } = await fixture(t, { analyze, timeoutMs: 40 });
  const a = (await call("analysis.start", source)).data;
  assert.equal(
    (await call("analysis.cancel", { jobId: a.id })).data.status,
    "cancelled",
  );
  const b = (await call("analysis.start", source)).data;
  assert.equal((await call("analysis.start", source)).status, 429);
  await new Promise((r) => setTimeout(r, 90));
  assert.equal(
    (await call("analysis.status", { jobId: a.id })).data.status,
    "cancelled",
  );
  assert.equal(
    (await call("analysis.status", { jobId: b.id })).data.status,
    "timed_out",
  );
});
test("engine failure does not crash discovery or leak exceptions", async (t) => {
  const { call } = await fixture(t, {
    analyze: async () => {
      throw Error("sensitive engine output");
    },
  });
  const a = (await call("analysis.start", source)).data;
  await new Promise((r) => setTimeout(r, 10));
  const result = (await call("analysis.status", { jobId: a.id })).data;
  assert.equal(result.status, "failed");
  assert.equal(result.error, "Analysis failed");
  assert.equal((await call("analysis.discover")).status, 200);
});

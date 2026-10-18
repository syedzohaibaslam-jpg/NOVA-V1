import { createServer } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import { analyzeSource, validateSource, limits } from "./analysis.mjs";

const tools = [
  "analysis.discover",
  "analysis.start",
  "analysis.status",
  "analysis.cancel",
];
const idPattern = /^[a-zA-Z0-9_-]{1,160}$/;
const terminal = new Set(["completed", "failed", "cancelled", "timed_out"]);
const equal = (a, b) => {
  const x = Buffer.from(a),
    y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

export function createAnalysisServer({
  credentials,
  analyze = analyzeSource,
  timeoutMs = 15000,
  maxJobs = 64,
  reaAvailable = false,
  audit = (event) => process.stdout.write(JSON.stringify(event) + "\n"),
}) {
  if (
    !Array.isArray(credentials) ||
    !credentials.length ||
    credentials.some(
      (c) =>
        !idPattern.test(c.organizationId) ||
        typeof c.token !== "string" ||
        c.token.length < 32,
    )
  )
    throw new Error(
      "Organization-bound credentials of at least 32 characters are required",
    );
  if (
    !Number.isFinite(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 60000 ||
    !Number.isInteger(maxJobs) ||
    maxJobs < 1 ||
    maxJobs > 256
  )
    throw new Error("Invalid resource limits");
  const jobs = new Map();
  const controllers = new Map();
  let active = 0;
  const log = (action, context, id) =>
    audit({
      action,
      organizationId: context.organizationId,
      projectId: context.projectId,
      jobId: id,
      timestamp: new Date().toISOString(),
    });
  const publicJob = (job) => ({
    id: job.id,
    status: job.status,
    progress: terminal.has(job.status) ? 100 : 10,
    result: job.result,
    error: job.error,
  });
  const server = createServer(async (req, res) => {
    const reply = (status, value) => {
      if (!res.writableEnded) {
        res.writeHead(status, {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        res.end(JSON.stringify(value));
      }
    };
    try {
      const token = String(req.headers.authorization || "").replace(
        /^Bearer /,
        "",
      );
      const credential = credentials.find((c) => equal(c.token, token));
      if (!credential) return reply(401, { error: "Unauthorized" });
      if (req.method !== "POST" || req.url !== "/tools/execute")
        return reply(404, { error: "Not found" });
      const chunks = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 1_500_000) {
          reply(413, { error: "Request too large" });
          req.destroy();
          return;
        }
        chunks.push(chunk);
      }
      let request;
      try {
        request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return reply(400, { error: "Invalid JSON" });
      }
      if (!request || !tools.includes(request.tool))
        return reply(400, { error: "Unknown tool" });
      const context = request.context;
      if (
        !context ||
        context.organizationId !== credential.organizationId ||
        !idPattern.test(context.projectId || "")
      )
        return reply(403, { error: "Invalid organization/project context" });
      if (request.tool === "analysis.discover")
        return reply(200, {
          tools,
          limits,
          engines: [
            { id: "nova-source-inventory", available: true },
            { id: "rea-javascript", available: reaAvailable },
            {
              id: "rea-jadx",
              available: false,
              reason: "Not exposed by this source-only adapter",
            },
            {
              id: "rea-ghidra",
              available: false,
              reason: "Not exposed by this source-only adapter",
            },
          ],
          persistence:
            "ephemeral; restart loses jobs; caller must persist completed evidence",
        });
      if (request.tool === "analysis.start") {
        let files;
        try {
          files = validateSource(request.input);
        } catch (error) {
          return reply(400, { error: error.message });
        }
        for (const [id, job] of jobs)
          if (terminal.has(job.status) && Date.now() - job.updatedAt > 300000)
            jobs.delete(id);
        if (active >= 2 || jobs.size >= maxJobs)
          return reply(429, { error: "Analysis capacity reached" });
        const id = randomUUID();
        const job = {
          id,
          organizationId: context.organizationId,
          projectId: context.projectId,
          status: "running",
          updatedAt: Date.now(),
        };
        const controller = new AbortController();
        jobs.set(id, job);
        controllers.set(id, controller);
        active++;
        const stop = (state) => {
          if (!terminal.has(job.status)) {
            job.status = state;
            job.updatedAt = Date.now();
            controller.abort();
            log("analysis." + state, context, id);
          }
        };
        const timer = setTimeout(() => stop("timed_out"), timeoutMs);
        log("analysis.started", context, id);
        // Retain capacity until the actual operation settles, even after cancellation.
        void Promise.resolve()
          .then(() => analyze(files, controller.signal))
          .then((result) => {
            if (!terminal.has(job.status)) {
              job.result = result;
              job.status = "completed";
              log("analysis.completed", context, id);
            }
          })
          .catch(() => {
            if (!terminal.has(job.status)) {
              job.status = "failed";
              job.error = "Analysis failed";
              log("analysis.failed", context, id);
            }
          })
          .finally(() => {
            clearTimeout(timer);
            controllers.delete(id);
            active--;
            job.updatedAt = Date.now();
          });
        return reply(202, publicJob(job));
      }
      const job = jobs.get(request.input?.jobId);
      if (
        !job ||
        job.organizationId !== context.organizationId ||
        job.projectId !== context.projectId
      )
        return reply(404, { error: "Job not found" });
      if (request.tool === "analysis.cancel" && !terminal.has(job.status)) {
        job.status = "cancelled";
        job.updatedAt = Date.now();
        controllers.get(job.id)?.abort();
        log("analysis.cancelled", context, job.id);
      }
      return reply(200, publicJob(job));
    } catch {
      reply(500, { error: "Analysis request failed" });
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.maxHeadersCount = 30;
  server.on("close", () => {
    for (const controller of controllers.values()) controller.abort();
  });
  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const credentials = JSON.parse(process.env.NOVA_ANALYSIS_CREDENTIALS || "[]");
  let analyze;
  if (process.env.NOVA_REA_SOURCE_ENABLED === "1") {
    const { createReaSourceAnalyzer } = await import("./rea-source.mjs");
    analyze = await createReaSourceAnalyzer();
  }
  const server = createAnalysisServer({
    credentials,
    analyze,
    reaAvailable: !!analyze,
  });
  // Loopback by default; use a private network/TLS proxy for remote Forge access.
  server.listen(
    Number(process.env.PORT || 4318),
    process.env.NOVA_ANALYSIS_HOST || "127.0.0.1",
  );
}

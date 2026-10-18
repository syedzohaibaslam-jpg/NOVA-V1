import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { analyzeSource } from "./analysis.mjs";

/** Reuse REA's shared CLI/MCP application service; never execute the submitted app. */
export async function createReaSourceAnalyzer() {
  const [{ analyzeJavaScriptApplication }, { ArtifactResourceScope }] =
    await Promise.all([
      import("../../dist/application/javascript/JavaScriptApplicationService.js"),
      import("../../dist/artifacts/ArtifactResourceScope.js"),
    ]);
  const retained = [];
  return async (files, signal) => {
    // Keep ownership when cleanup fails, and retry before admitting more work.
    while (retained.length) {
      const previous = retained[0];
      await previous.scope.close();
      await rm(previous.root, { recursive: true, force: true });
      retained.shift();
    }
    const report = await analyzeSource(files, signal);
    if (!files.some((file) => /\.(js|jsx|mjs|cjs|ts|tsx)$/.test(file.path)))
      return report;
    const root = await mkdtemp(join(tmpdir(), "nova-rea-"));
    const scope = new ArtifactResourceScope();
    try {
      for (const file of files) {
        signal.throwIfAborted();
        const target = join(root, file.path);
        await mkdir(dirname(target), { recursive: true });
        await writeFile(target, file.content, { flag: "wx", mode: 0o600 });
      }
      const result = await analyzeJavaScriptApplication(
        { input_path: root },
        scope,
        { signal },
      );
      signal.throwIfAborted();
      if (!result.ok)
        return {
          ...report,
          limitations: [
            ...report.limitations,
            "REA JavaScript analysis could not complete; source inventory remains available.",
          ],
        };
      // Keep the producing engine's Evidence intact. Oversized evidence is not silently truncated.
      const evidence = result.value;
      if (Buffer.byteLength(JSON.stringify(evidence)) > 600000)
        return {
          ...report,
          limitations: [
            ...report.limitations,
            "REA evidence exceeded the inline transport limit and was omitted.",
          ],
        };
      return {
        ...report,
        engine: "nova-source-inventory+rea-javascript",
        reaEvidence: evidence,
        limitations: report.limitations
          .filter((s) => !s.startsWith("No semantic"))
          .concat(
            "REA JavaScript static analysis; no build or runtime verification.",
          ),
      };
    } finally {
      try {
        await scope.close();
        await rm(root, { recursive: true, force: true });
      } catch (error) {
        retained.push({ scope, root });
        throw error;
      }
    }
  };
}

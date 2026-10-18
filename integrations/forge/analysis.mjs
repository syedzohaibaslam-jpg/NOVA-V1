import { createHash } from "node:crypto";

export const limits = Object.freeze({
  files: 128,
  sourceBytes: 1_000_000,
  fileBytes: 128_000,
});

export function validateSource(input) {
  if (
    !input ||
    input.authorization !== "authorized" ||
    !Array.isArray(input.files) ||
    !input.files.length ||
    input.files.length > limits.files
  )
    throw new Error("Invalid authorized source snapshot");
  let bytes = 0;
  const paths = new Set();
  return input.files.map((file) => {
    if (
      !file ||
      typeof file.path !== "string" ||
      typeof file.content !== "string"
    )
      throw new Error("Invalid source file");
    const path = file.path;
    if (
      path.length > 240 ||
      !path ||
      /[\\\x00-\x1f:]/.test(path) ||
      path.startsWith("/") ||
      path
        .split("/")
        .some(
          (p) =>
            !p ||
            p === "." ||
            p === ".." ||
            p === ".git" ||
            p === "node_modules" ||
            p === ".env" ||
            p.startsWith(".env."),
        ) ||
      paths.has(path)
    )
      throw new Error("Unsafe or duplicate source path");
    const size = Buffer.byteLength(file.content);
    bytes += size;
    if (size > limits.fileBytes || bytes > limits.sourceBytes)
      throw new Error("Source size limit exceeded");
    paths.add(path);
    return { path, content: file.content };
  });
}

export async function analyzeSource(files, signal) {
  const findings = [];
  const inventory = [];
  for (const file of files) {
    signal.throwIfAborted();
    const sha256 = createHash("sha256").update(file.content).digest("hex");
    inventory.push({
      path: file.path,
      sha256,
      bytes: Buffer.byteLength(file.content),
    });
    const evidence = { path: file.path, sha256 };
    if (file.path.endsWith("package.json")) {
      try {
        const value = JSON.parse(file.content);
        findings.push({
          kind: "package-manifest",
          confidence: "observed",
          evidence,
          detail: {
            name:
              typeof value.name === "string" ? value.name.slice(0, 200) : null,
            scripts:
              value.scripts && typeof value.scripts === "object"
                ? Object.keys(value.scripts).slice(0, 40)
                : [],
            electron: !!(
              value.dependencies?.electron || value.devDependencies?.electron
            ),
          },
        });
      } catch {
        findings.push({
          kind: "invalid-json",
          confidence: "observed",
          evidence,
          detail: "Package manifest is not valid JSON.",
        });
      }
    }
    if (/\.(java|kt|kts|js|jsx|ts|tsx)$/.test(file.path))
      findings.push({
        kind: "source-file",
        confidence: "observed",
        evidence,
        detail: {
          language: file.path.split(".").pop(),
          lines: file.content.split("\n").length,
        },
      });
    if (/AndroidManifest\.xml$/.test(file.path))
      findings.push({
        kind: "android-manifest-present",
        confidence: "observed",
        evidence,
        detail:
          "Manifest file supplied; not compiled or validated by Android tools.",
      });
    if (
      /(fabric\.mod\.json|mods\.toml|neoforge\.mods\.toml|manifest\.json)$/.test(
        file.path,
      )
    )
      findings.push({
        kind: "mod-manifest-candidate",
        confidence: "inferred",
        evidence,
        detail:
          "Possible mod/add-on manifest; framework compatibility not verified.",
      });
    if (/\.(log|crash|txt)$/.test(file.path)) {
      const lines = file.content.split("\n");
      const matches = lines
        .flatMap((line, i) =>
          /Exception|Error:|FATAL|Caused by:/.test(line)
            ? [{ line: i + 1, excerpt: line.slice(0, 300) }]
            : [],
        )
        .slice(0, 20);
      if (matches.length)
        findings.push({
          kind: "crash-log-markers",
          confidence: "observed",
          evidence,
          detail: matches,
        });
    }
    // Yield between bounded files so cancellation and HTTP progress can run.
    await new Promise((resolve) => setImmediate(resolve));
  }
  return {
    schemaVersion: 1,
    engine: "nova-source-inventory",
    findings,
    inventory,
    limitations: [
      "Static source inventory only; source is never executed.",
      "No semantic decompilation, build, runtime performance, or vulnerability claims.",
      "JADX/Ghidra require separately installed REA engines.",
    ],
    coverage: { examinedFiles: files.length, suppliedFiles: files.length },
  };
}

# Forge analysis adapter — tested development candidate

This optional adapter leaves REA's CLI/MCP architecture intact. It does not expose the unrestricted MCP catalog, execute uploaded code, or run arbitrary commands.

## Implemented

- Authenticated POST `/tools/execute` with `analysis.discover`, `analysis.start`, `analysis.status`, `analysis.cancel`.
- Tokens are bound to organizations by server configuration. Project IDs partition jobs. The trusted Forge caller must authorize project access.
- Source snapshots only: Java/Kotlin/JavaScript inventory, package manifests, candidate mod manifests, crash-log markers, SHA-256 provenance, confidence and limitations.
- Optional REA JavaScript application analysis reuses the shared CLI/MCP application service and its existing process supervision/resource scope. No uploaded application execution.
- Two active jobs, 128 files, 128 KB per file, 1 MB source, 1.5 MB request, 15-second job timeout, 64 retained jobs, five-minute terminal-result retention. Cancellation retains capacity until engine cleanup settles.
- Audit events omit tokens and submitted source. Forge persists complete reports in its existing artifact store.

## Run without external services

Set `NOVA_ANALYSIS_CREDENTIALS` through your secret manager to a JSON array containing `{ "organizationId": "your-org", "token": "a-random-secret-at-least-32-characters" }`. Generate a different random token for each organization. Do not commit credentials.

`node integrations/forge/server.mjs` listens on loopback port 4318. All routes require authentication, including discovery. Change `PORT` if required. Do not publicly expose a plain HTTP listener; use an authenticated HTTPS proxy or a controlled private network.

For source-only containers, build with `docker build -f integrations/forge/Dockerfile .`; impose CPU/memory/PID limits, a read-only root filesystem and a bounded writable `/tmp` at deployment. The container runs as non-root. The image does not contain REA engine dependencies.

Optional REA mode requires `npm ci`, `npm run build:cached`, a functional procps-compatible `ps` and REA's normal worker prerequisites. Set `NOVA_REA_SOURCE_ENABLED=1` only after verification on the target host. A missing build fails startup; runtime engine failure returns source inventory with an explicit limitation. Never disable process-ownership safeguards to make a test pass.

## Test

`node --test integrations/forge/server.test.mjs`

Cross-repository smoke: in Forge run `npm run core:check`, then `NOVA_V1_PATH=/absolute/path/NOVA-V1 node --test scripts/nova-analysis-smoke.cjs`.

## Verification and limits (2026-10-18 IST)

Four HTTP/lifecycle tests passed. Existing REA runtime/skill build passed. Real REA JavaScript invocation was attempted but blocked by this execution host's `ps` reporting `fatal library error, lookup self`. The fallback reports that analysis did not complete; no semantic-engine success is claimed.

APK upload/decompilation, native Ghidra, JAR compilation, and live game compatibility are not implemented by this adapter. Existing REA tools remain available independently with their own dependencies. The source service is not a substitute for those engines.

Jobs are ephemeral and not restart-resumable. No background queue durability is claimed here; Forge's mission queue remains Postgres-backed. Full live AI/chat/APK verification and production isolation remain deployment gates. No deployment or paid model call was performed.

# NOVA-V1 Game Analysis Lab (development plan)

Status: tested development adapter implemented; not deployed. See [implementation, tests and limitations](../integrations/forge/README.md).

The source-analysis HTTP lifecycle and Forge Postgres integration were exercised locally. Real REA semantic analysis is environment-blocked; APK/native engine integration and live production acceptance remain incomplete. The original proposal below describes the broader target, not completed functionality.

## Purpose
Use the existing REA MCP engine for authorized game reverse engineering and original mod/tool development. Keep NOVA-V1 and NOVA Forge independently deployable.

## Proposed workflow
1. Forge chat receives a request and asks for the target, platform, and authorization.
2. An isolated analysis worker accepts user-owned, open-source, or otherwise authorized artifacts.
3. REA's existing static analyzers return evidence and limitations. Use optional JADX/Ghidra only where installed and supported.
4. Forge coding agent generates original mod/tool source using documented modding APIs.
5. Android worker builds APKs for Android projects; Java Minecraft mods produce JARs, not APKs.
6. Verify build artifacts, test results, and checksums before presenting a download in Forge chat.

## Integration contract (proposal)
- `POST /analysis/jobs`: authenticated request with artifact reference, target type, authorization declaration, and requested analysis.
- `GET /analysis/jobs/:id`: queued/running/completed/failed status and sanitized report.
- `POST /analysis/jobs/:id/cancel`: cancel and clean temporary files.
- Do not expose the REA MCP server publicly. Use an authenticated Forge-side adapter, strict timeouts, resource limits, isolated filesystem and audit logs.
- Never execute untrusted uploaded binaries directly on the Forge web service.
- Restrict analysis and generated artifacts to authorized research, interoperability, modding, and defensive testing; no multiplayer cheats, anti-cheat bypass, credential theft or unauthorized tampering.

## First acceptance test
Use a small open-source Android demo or user-owned sample project. Verify static analysis report, Forge agent tool call, Android worker build, APK signature, installability and chat artifact link.

## Next implementation steps
- Inspect Forge's existing MCP/tool registration, queue, auth and Android artifact delivery code.
- Implement the adapter behind a feature flag without changing existing production routes.
- Add unit/integration tests with a mock REA MCP server.
- Deploy only after isolated tests pass and explicit approval.

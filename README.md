# Mantis

Working name. Native, cross-platform web application security testing toolkit written in Rust.
No Electron, no webview. Targets Windows, Linux, macOS.

## Goals
- Intercepting HTTP(S)/WebSocket proxy with full-fidelity raw message handling.
- Replay, fuzzing, entropy analysis, passive and active scanning, out-of-band interaction server.
- Extension runtime (WASM first).
- Modern native GUI, plus a headless CLI that shares the same core.
- No AI features.

## Status
Implemented: raw HTTP/1.1 wire layer, SQLite store, scope, HTTP/HTTPS/WebSocket proxy with local CA,
intercept queue, match-and-replace, CLI, and a desktop UI (history, viewer, proxy, scope, intercept).
Planned crates below are still empty. See docs/ROADMAP.md.

Get started with docs/USAGE.md.

## Responsible use
This tool sends attack traffic. Use it only against systems you own or are authorised in writing to test.

## Repo layout (target)
```
mantis/
  Cargo.toml            # workspace
  CLAUDE.md
  docs/
  .claude/
  crates/
    mantis-core/        # message model, raw HTTP, storage, scope
    mantis-proxy/       # MITM listener, CA, TLS
    mantis-replay/
    mantis-fuzz/
    mantis-entropy/
    mantis-scan/
    mantis-oob-server/  # separate self-hostable binary
    mantis-ext/
    mantis-ui/
    mantis-cli/
```

## Docs index
- docs/USAGE.md - build, CLI reference, scope file, project database
- docs/PRD.md - requirements and non-goals
- docs/ARCHITECTURE.md - crates, data flow, key decisions
- docs/ROADMAP.md - phases with acceptance criteria
- docs/SECURITY_AND_SCOPE.md - safety rules for a tool that sends attack traffic
- docs/TESTING.md - test strategy and lab targets
- docs/CLAUDE_CODE_SETUP.md - how to start working with Claude Code
- docs/PROMPTS.md - ready-to-paste prompts for each phase
- docs/HTTPS_INTERCEPTION.md - CA setup, key handling, limits
- docs/INTERCEPT_AND_REWRITE.md - intercept queue and match-and-replace rules
- docs/WEBSOCKET.md - WebSocket frame capture
- docs/UI.md - desktop UI guide and benchmark
- docs/adr/ - architecture decision records (0001 GUI framework, 0002 HTTP/2 downgrade)

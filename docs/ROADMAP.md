# Roadmap

Each item is complete only when its acceptance criteria pass and fmt/clippy/tests are green.

## Phase 0 - Foundations and spikes
- [x] Workspace, CI (Windows/Linux/macOS matrix), rust-toolchain.toml, LICENSE choice.
- [x] GUI spike: one window with a 5 MB text body viewer, hex view, search, in iced, Slint, and egui.
  Acceptance: scroll stays smooth; non-UTF-8 bytes render; decision recorded as ADR.

## Phase 1 - Core and wire
- [x] Message model (raw + derived view), SQLite storage with migrations.
- [x] Raw HTTP/1.1 writer/reader. Acceptance: round-trip tests preserve malformed headers, duplicate headers, bare LF, obs-fold.
- [x] Scope model (include/exclude by host, port, path regex).

## Phase 2 - Proxy
- [x] HTTP proxy on localhost, logging to SQLite.
- [ ] CA generation, export, per-host leaf certs, HTTPS interception. Acceptance: browser with CA loads an HTTPS site through the proxy.
- [x] Intercept queue (forward/drop/edit) and match-and-replace.
- [ ] WebSocket capture. HTTP/2 support or documented downgrade.

## Phase 3 - Minimal GUI
- [ ] History table (virtualized), message viewer/editor, intercept panel, scope settings.
  Proxy settings must expose the same options as the CLI, including `insecure_upstream` (skip origin
  certificate verification): off by default, with a visible warning whenever it is on.
  Acceptance: 100k rows scroll smoothly; no UI blocking during proxying.

## Phase 4 - Replay, Codec, Diff
- [ ] Replay tabs with history. Codec chains. Diff view.

## Phase 5 - Fuzzer
- [ ] Four attack modes, payload sources/processors, grep match/extract, rate limiting, result table.

## Phase 6 - Entropy analyzer
- [ ] Token capture, bit-level and character-level tests, entropy estimate, report.

## Phase 7 - Browser integration
- [ ] Launch Chromium with dedicated profile, proxy, and CA trust. DevTools Protocol control.

## Phase 8 - Scanner
- [ ] Crawler (static, then DevTools-driven for SPAs).
- [ ] Passive checks: security headers, cookie flags, information disclosure, reflected input.
- [ ] Active checks: SQLi, XSS, path traversal, SSRF, command injection (one module each).
- [ ] Issue model, dedup, severity/confidence, HTML/JSON report.
  Acceptance: documented detection results on the lab targets in docs/TESTING.md, with false-positive notes.

## Phase 9 - OOB server
- [ ] DNS, HTTP(S), SMTP listeners, correlation IDs, client polling API, deployment doc.

## Phase 10 - Extensions
- [ ] WASM host API v0, example plugins (custom check, payload generator).

## Phase 11 - Release
- [ ] Packaging, code signing/notarization, update docs, user manual.

# Architecture

## Crates
| Crate | Responsibility | Depends on |
|-------|----------------|-----------|
| mantis-core | Message model, raw wire I/O, storage, scope, events | - |
| mantis-proxy | Listener, CA management, TLS interception, intercept queue | core |
| mantis-replay | Replay sessions | core |
| mantis-fuzz | Attack engine, payloads, rate limiter | core |
| mantis-entropy | Token statistics | core |
| mantis-scan | Crawler, checks, issues | core, replay |
| mantis-oob-server | Standalone interaction server | - |
| mantis-ext | WASM runtime (wasmtime), host API | core |
| mantis-ui | Native GUI | all libs |
| mantis-cli | Headless frontend | all libs |

## Data flow
client -> proxy listener -> TLS terminate -> parse (derive view, keep raw) -> intercept queue
-> upstream (raw writer) -> response -> store in SQLite -> broadcast event -> UI / extensions.

## Implemented so far
Crates not listed here are still empty (Phase 4 onward).

**mantis-core** (no UI, no listeners)
- `message`: `Exchange`, `Summary`, `WsFrame`; raw `Bytes` plus derived lookup columns.
- `view`: `RequestView` / `ResponseView`, derived on demand, never stored in place of the raw bytes.
- `wire`: raw HTTP/1.1 `Reader` (finds message boundaries without rewriting), `write_raw`, the
  explicit `fix_content_length` helper, and the incremental WebSocket `FrameScanner`.
- `scope`: default-deny include/exclude rules (host, ports, path regex), TOML load/save.
- `store`: SQLite `Store` with numbered migrations, filtered and paged listing, a read-only open for
  readers, and `ws_frames` per exchange.

**mantis-proxy**
- `serve(Config, Store)` returns a `ProxyHandle` and runs on tokio. One writer thread owns the store
  connection; connection tasks send it `LogCmd`s over a channel.
- `conn`: one request loop for plain HTTP and for requests decrypted from a `CONNECT` tunnel. Bytes are
  forwarded as read; capture happens on the side. WebSocket upgrades switch to frame capture.
- `ca` / `tls`: local CA (rcgen) with an owner-only key, per-host leaf cache (LRU), rustls on both sides,
  `http/1.1` only (ADR 0002). `target`: where a request goes, kept from the original request.
- `rewrite`: match-and-replace rules, hot-swappable. `intercept`: per-direction hold queue with
  Forward / Edited / Drop decisions. Per message the order is scope, rewrite, intercept, forward.
- Events out: `subscribe()` (history rows), `subscribe_ws()` (frames), `intercept().subscribe()` (held).

**mantis-cli**: `proxy` and `ca` subcommands over the library; stdin prompt for the intercept queue.

**mantis-ui** (egui, ADR 0001)
- `backend`: runs the proxy on a background runtime. The UI sends `Cmd`s and polls `Event`s, with a
  wake callback to repaint, so the UI thread never waits on I/O.
- View-models carry the logic and are tested without rendering: `HistoryModel` (paged rows through a
  reader thread with its own read-only connection), `RawView` (display rows, Text/Hex, search),
  `escape` (byte-exact escaped-text editing), `settings`, `scope_editor`, `intercept`.
- `app` / `pages` only draw. `bench` is the scripted scroll benchmark; `tests/load.rs` checks the UI
  stays responsive under proxy load.

## Key decisions (record changes as ADRs in docs/adr/)
1. Raw bytes are the source of truth. Parsed views are derived.
2. Own HTTP/1.1 writer for outbound test traffic; hyper only for well-formed internal use.
3. rustls + rcgen; per-host leaf cert cache.
4. SQLite with blob bodies; indexes on host, method, status, time.
5. Event bus: tokio broadcast for history events, mpsc for commands.
6. GUI framework: egui/eframe (ADR 0001).
7. Browser integration is an external Chromium process controlled via DevTools Protocol.
8. Extensions: WASM via wasmtime with capability-limited host API.
9. Scan checks are modules behind one trait; a declarative template format is a later option.

## Candidate libraries (verify versions and maintenance before adopting)
hudsucker or a custom hyper/rustls MITM, rcgen, rustls, tokio, rusqlite, thiserror, anyhow,
chromiumoxide, wasmtime, clap, tracing.

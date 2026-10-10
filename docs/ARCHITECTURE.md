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

## Key decisions (record changes as ADRs in docs/adr/)
1. Raw bytes are the source of truth. Parsed views are derived.
2. Own HTTP/1.1 writer for outbound test traffic; hyper only for well-formed internal use.
3. rustls + rcgen; per-host leaf cert cache.
4. SQLite with blob bodies; indexes on host, method, status, time.
5. Event bus: tokio broadcast for history events, mpsc for commands.
6. GUI framework is chosen after the editor-widget spike (see ROADMAP phase 0). Candidates: iced, Slint, egui.
7. Browser integration is an external Chromium process controlled via DevTools Protocol.
8. Extensions: WASM via wasmtime with capability-limited host API.
9. Scan checks are modules behind one trait; a declarative template format is a later option.

## Candidate libraries (verify versions and maintenance before adopting)
hudsucker or a custom hyper/rustls MITM, rcgen, rustls, tokio, rusqlite, thiserror, anyhow,
chromiumoxide, wasmtime, clap, tracing.

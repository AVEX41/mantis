# Mantis - project instructions

Native Rust security-testing toolkit (intercepting proxy, replay, fuzzer, scanner, OOB server).
No webview, no Electron, no AI features. Never reference other commercial products in code, docs, or commits.

## Commands
- Build: `cargo build --workspace`
- Test: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Format: `cargo fmt --all`
- Run CLI: `cargo run -p mantis-cli -- --help`
- Run UI: `cargo run -p mantis-ui`
- Definition of done: fmt, clippy, and tests all pass.

## Architecture rules
- Read docs/ARCHITECTURE.md before changing crate boundaries.
- `mantis-core` has no UI and no network-listener code. UI crates depend on core, never the reverse.
- Messages are stored as raw `Bytes`. The parsed view is derived and must never replace the raw form.
- Do not route Replay or Fuzz traffic through `hyper` client types. Use the raw writer in `mantis-core::wire`
  so malformed requests, duplicate headers, and odd line endings are preserved.
- TLS: rustls + rcgen only. No OpenSSL dependency (cross-platform builds).
- Async runtime: tokio. Components talk via channels; the UI thread never blocks on I/O.
- Storage: SQLite (rusqlite). Schema changes need a numbered migration in `crates/mantis-core/migrations/`.

## Code style
- Rust 2021+, stable toolchain pinned in `rust-toolchain.toml`.
- No `unwrap()`/`expect()` outside tests. Use `thiserror` in libraries, `anyhow` in binaries.
- Public items need doc comments. Prefer small modules over large files.
- Every new feature ships with tests. Parser and wire code needs property or fuzz tests.

## Workflow
- Start non-trivial work in plan mode. State the plan, wait for approval.
- One phase item from docs/ROADMAP.md per branch. Small commits, conventional commit messages.
- Check the item's acceptance criteria before declaring it done.
- Update docs/ROADMAP.md checkboxes when an item is complete.

## Safety (details in docs/SECURITY_AND_SCOPE.md)
- Active scanning and fuzzing must refuse out-of-scope hosts by default.
- Never commit generated CA private keys, captured traffic, or project databases.
- Test only against local lab targets listed in docs/TESTING.md.

# Mantis - project instructions

Native Rust security-testing toolkit (intercepting proxy, replay, fuzzer, scanner, OOB server).
No webview, no Electron, no AI features. Never reference other commercial products in code, docs, or commits.

Status: pre-code (Phase 0). There's no Cargo workspace yet. The target crate layout is in README.md and
docs/ARCHITECTURE.md; follow it rather than inventing one. The commands below apply once the workspace exists.

## Commands
- Build: `cargo build --workspace`
- Test: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Run CLI: `cargo run -p mantis-cli -- --help`
- Run UI: `cargo run -p mantis-ui` (GUI framework not chosen yet: the iced/Slint/egui spike is ARCHITECTURE
  decision 6. Don't pick one on your own.)
- Fuzz: `cargo fuzz run <target>` (cargo-fuzz; targets go in `fuzz/`)
- Definition of done: fmt, clippy, and tests all pass.

## Architecture rules
- Read docs/ARCHITECTURE.md before changing crate boundaries.
- Record architectural decisions as ADRs in `docs/adr/`.
- `mantis-core` has no UI and no network-listener code. UI crates depend on core, never the reverse.
- `mantis-oob-server` is a standalone binary that depends on no other mantis crate, including core.
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
- Every new feature ships with tests. Parser and wire code needs proptest property tests or cargo-fuzz targets.
- Testing rules, including report golden files and the scanner "done" criteria, are in @docs/TESTING.md.

## Commits (strict)
- NEVER run `git commit`, `git push`, `git tag`, or rewrite history. The user commits manually.
- NEVER add `Co-Authored-By`, "Generated with", or any mention of Claude/AI in commit messages or files.
- When a unit of work is finished, stop and output a ready-to-paste commit message in a code block:
  Conventional Commits subject (max 72 chars, imperative), blank line, short body explaining why,
  plus the exact `git add <paths>` command listing only the files that belong in the commit.
- Run `git add` only if the user asks. Otherwise just print the command.

## Workflow
- Start non-trivial work in plan mode. State the plan, wait for approval.
- One phase item from docs/ROADMAP.md per branch. Small logical units; propose commit messages (see Commits).
- Check the item's acceptance criteria before declaring it done.
- Update docs/ROADMAP.md checkboxes when an item is complete.

## Safety (details in docs/SECURITY_AND_SCOPE.md)
- Active scanning and fuzzing must refuse out-of-scope hosts by default.
- Never commit generated CA private keys, captured traffic, or project databases.
- Test only against local lab targets listed in docs/TESTING.md.

# Usage

What works today: the HTTP/HTTPS/WebSocket proxy, scope, intercept, match-and-replace, SQLite
history, and a desktop UI over the same pieces. Replay, fuzzing, scanning and the rest are on the
[roadmap](ROADMAP.md).

## Build and run
```
cargo build --workspace
cargo run -p mantis-cli -- --help
cargo run --release -p mantis-ui -- [PROJECT.db]
```
Definition of done for any change: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`
and `cargo test --workspace` all pass.

## Quick start (CLI)
```
cargo run -p mantis-cli -- ca export --out mantis-ca.pem     # import into the test browser/profile
cargo run -p mantis-cli -- proxy --db lab.db --scope scope.toml
curl --proxy http://127.0.0.1:8080 --cacert mantis-ca.pem https://example.org/
```
Each logged exchange prints as `#<id> <method> <host>:<port> <path> -> <status>`; WebSocket frames as
`ws #<exchange> -> text 12B`. Ctrl-C stops the proxy. Point the client at `127.0.0.1:8080`.

## `mantis-cli proxy`
| Flag | Default | Meaning |
|------|---------|---------|
| `--listen ADDR` | `127.0.0.1:8080` | Listen address. |
| `--db PATH` | `mantis.db` | Project database, created if missing. |
| `--scope FILE` | none (everything in scope) | Scope TOML, see below. |
| `--allow-non-loopback` | off | Required to listen beyond loopback; exposes the proxy to the network. |
| `--ca-dir DIR` | user data dir (`<data>/mantis/ca`) | Where `ca.pem` / `ca.key` live. |
| `--rules FILE` | none | Match-and-replace rules ([INTERCEPT_AND_REWRITE.md](INTERCEPT_AND_REWRITE.md)). |
| `--intercept` | off | Hold in-scope requests; answer `f` (forward) or `d` (drop) on stdin. |
| `--intercept-responses` | off | Also hold responses. |
| `--insecure-upstream` | off | Do not verify origin certificates. Lab targets only. |

## `mantis-cli ca`
- `ca path` prints the CA directory.
- `ca export --out FILE [--format pem|der]` writes the certificate only (never the key) and refuses to
  overwrite. Both accept `--ca-dir`. Details and key handling: [HTTPS_INTERCEPTION.md](HTTPS_INTERCEPTION.md).

## Scope file
Default deny: a target is in scope only if an include rule matches and no exclude rule matches.
```toml
[[rules]]
action = "include"            # include | exclude
host = "*.lab.test"           # exact host, IP literal, or *.suffix (subdomains only, not the apex)
ports = ["80", "8000-8999"]   # optional; omitted means any port
path = "/api/.*"              # optional regex, must match the whole path (query excluded)

[[rules]]
action = "exclude"
host = "admin.lab.test"
```
Unknown keys are errors. Paths are matched as sent (no percent-decoding), so an exclude on `/admin` does
not cover `/%61dmin`. With no scope the proxy treats everything as in scope. With one, out-of-scope
requests are relayed untouched, never held, rewritten or logged. The UI edits the same file format.

## Desktop UI
Run `mantis-ui`, open or create a project, start the proxy from the Proxy page. Pages, the escaped-text
editor, and the 100k-row benchmark are in [UI.md](UI.md).

## Project database
One SQLite file per project (tables `exchanges`, `ws_frames`; migrations in
`crates/mantis-core/migrations/`). Raw `request` / `response` bytes are the source of truth; `host`,
`method`, `path`, `status` are derived for lookup. `request_original` / `response_original` keep what was
captured when a rewrite rule or edit changed it. Project files and the CA key can hold credentials and
traffic: never commit them or share them unredacted.

## Safety reminders
- Use only against your own lab targets ([TESTING.md](TESTING.md)) or systems you are authorised to test.
- Anyone holding `ca.key` can impersonate sites to clients that trust the CA; remove the CA from the
  browser profile when done.
- HTTP/2 is downgraded to HTTP/1.1 ([ADR 0002](adr/0002-http2-downgrade.md)); gRPC cannot be proxied.

## Where the code lives
| Area | Location |
|------|----------|
| Message model, store, scope | `crates/mantis-core` |
| Raw HTTP/1.1 reader/writer, `Content-Length` fix helper, WebSocket frame scanner | `crates/mantis-core/src/wire` |
| Proxy, CA, TLS, intercept queue, rewrite rules | `crates/mantis-proxy` |
| Headless frontend | `crates/mantis-cli` |
| Desktop UI and its view-models | `crates/mantis-ui` |
| WebSocket capture | [WEBSOCKET.md](WEBSOCKET.md) |

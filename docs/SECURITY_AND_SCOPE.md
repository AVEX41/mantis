# Security and scope rules

This tool sends attack traffic. Build safety in from the start.

- Scope is required: active scan and fuzz refuse targets outside the configured scope unless explicitly overridden per run.
- Private key material (local CA) is stored in the user data dir with owner-only permissions. Never committed.
- Captured traffic and project files may contain credentials. Provide redaction on export.
- Rate limits default to conservative values. Show the target and rate before starting a run.
- Extensions run in a WASM sandbox with explicit capabilities (no filesystem or network unless granted).
- OOB server: authenticate polling API, rate limit, and document abuse risks.
- Development testing only against local lab targets (see TESTING.md). Never against third-party systems without written authorization.
- Dependency hygiene: `cargo audit` and `cargo deny` in CI.
- Responsible-use notice in README and first-run dialog.

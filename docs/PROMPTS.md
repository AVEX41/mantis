# Prompts for Claude Code

Use plan mode (Shift+Tab until "plan mode on") for each of these. Review the plan before approving.

## Kickoff
```
Read CLAUDE.md and all files in docs/. Do not write code yet.
Summarize the project in 10 lines, list ambiguities or risks in the docs,
and propose the exact Cargo workspace layout and dependency list for Phase 0.
```

## Phase 0: workspace
```
Implement the Phase 0 workspace item only: Cargo workspace with the crates in docs/ARCHITECTURE.md as empty
libraries/binaries, rust-toolchain.toml, .gitignore (include CA keys, *.mantis, *.db), and a GitHub Actions
matrix for Windows/Linux/macOS running fmt, clippy, test. Verify with the commands in CLAUDE.md.
Do not commit; give me the commit message and git add command.
```

## Phase 0: GUI spike
```
Create a throwaway spike in spikes/gui-<framework>/ for iced, Slint, and egui. Each shows a 5 MB body,
a hex view, and search. Measure scroll smoothness and memory. Write findings to docs/adr/0001-gui-framework.md
with a recommendation. Do not touch crates/.
```

## Phase 1: wire
```
Implement mantis-core::wire: a raw HTTP/1.1 request/response reader and writer that preserves bytes exactly.
Write the tests first (malformed headers, duplicate headers, bare LF, obs-fold, chunked edge cases),
show them failing, then implement.
```

## Phase 2: proxy
```
Implement the HTTP-only proxy listener in mantis-proxy that stores each exchange in SQLite via mantis-core.
Then stop and report before starting TLS interception.
```

## Review loop (after each item)
```
Use the code-reviewer subagent on the diff. Then check the acceptance criteria in docs/ROADMAP.md
for this item and report pass/fail per criterion.
```
Then run `/commit-msg`. Claude prints the message and `git add` command; you commit yourself.

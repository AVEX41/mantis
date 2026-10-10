# Starting with Claude Code

## 1. Prerequisites
- Rust via rustup (stable). Add components: `rustup component add rustfmt clippy`.
- Git, and a GitHub repo (private at first).
- Optional tools: `cargo install cargo-audit cargo-deny cargo-fuzz` (run these yourself).
- Docker for lab targets.

## 2. Install Claude Code
Follow the official install instructions at https://code.claude.com/docs (native installer recommended;
check the docs for the current command for your OS). Then run `claude` once in a terminal and log in.

## 3. Create the repo
```
mkdir mantis && cd mantis
git init
# copy this docs bundle into the folder (README.md, CLAUDE.md, docs/, .claude/)
git add . && git commit -m "docs: initial project documentation"
```

## 4. Understand what each file does
| File | Purpose |
|------|---------|
| CLAUDE.md | Loaded every session. Keep under ~200 lines. Commands, rules, workflow. |
| .claude/settings.json | Permissions (allow/ask/deny) and hooks. Shared via git. |
| .claude/settings.local.json | Your personal approvals. Add to .gitignore. |
| .claude/agents/*.md | Subagents with separate context (reviewers). |
| docs/* | Reference material Claude reads on demand. Not loaded every session. |

## 5. First session
1. `cd mantis && claude --permission-mode plan`
2. Run `/permissions` and confirm the allow/ask/deny rules loaded.
3. Paste the "Kickoff" prompt from docs/PROMPTS.md.
4. Read the plan. Fix misunderstandings in the docs, not only in chat, so they persist.
5. Approve, and let it implement one roadmap item only.

## 6. Working loop (per roadmap item)
1. New branch: `git switch -c phase-1-wire`.
2. Plan mode: ask for a plan for that single item. Approve or edit it.
3. Implement with tests first where the item says so.
4. Verify: Claude runs fmt, clippy, test. You also run them.
5. Review: ask for the code-reviewer subagent (and security-reviewer when relevant).
6. Read the diff yourself. You are the mentor-grade check; do not merge what you cannot explain.
7. Commit, merge, tick the box in docs/ROADMAP.md, and start a fresh session (`/clear`) for the next item.

## 7. Habits that keep quality high
- One task per session. Clear context between unrelated tasks.
- Give Claude a way to verify its own work: tests, clippy, a reproducible command.
- Put recurring corrections into CLAUDE.md. Use `/init` later to compare against what it infers.
- Record design decisions as ADRs in docs/adr/.
- Use hooks for things that must always happen (formatting). Use CLAUDE.md for guidance.
- Use git worktrees for parallel sessions only when tasks touch different crates.
- Review dependencies Claude adds (`cargo add` is set to ask). Check maintenance, license, and unsafe usage.

## 8. .gitignore essentials
```
/target
.claude/settings.local.json
CLAUDE.local.md
*.pem
*.key
*.mantis
*.db
```

## 9. Learn while building
Because your goal is understanding, ask Claude to explain each module after implementation, then rewrite one
small function yourself without help. Keep a `docs/LEARNING.md` with what you learned per phase.

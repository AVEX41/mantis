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
You make this commit yourself. Claude is configured never to commit.

## 4. What each file does
| File | Purpose |
|------|---------|
| CLAUDE.md | Loaded every session. Keep under ~200 lines. Commands, rules, workflow. |
| .claude/settings.json | Permissions (allow/ask/deny), attribution, hooks. Shared via git. |
| .claude/settings.local.json | Your personal approvals. Add to .gitignore. |
| .claude/agents/*.md | Subagents with separate context (reviewers, on a cheaper model). |
| .claude/commands/commit-msg.md | `/commit-msg`: prints a commit message and git add command. |
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
6. Read the diff yourself. Do not merge what you cannot explain.
7. Run `/commit-msg`. Claude prints the `git add` command and commit message; you run them yourself,
   merge, tick the box in docs/ROADMAP.md, and `/clear` for the next item.

## 7. Commit policy (you commit, not Claude)
Three layers, because natural-language rules alone can be ignored:
1. `attribution.commit` and `attribution.pr` set to empty strings plus `sessionUrl: false` remove the trailer and footer.
   A GitHub issue reports the empty-string setting not working in some versions, which is why layers 2 and 3 exist.
2. `permissions.deny` blocks `git commit`, `git push`, `git tag`, `git rebase`, and `git reset --hard`. This is the hard guarantee.
3. CLAUDE.md and `/commit-msg` tell Claude to output a message and `git add` command instead.
`includeGitInstructions: false` removes Claude Code's built-in commit workflow prompt so it does not compete with your rules.
Verify once: ask Claude to commit a trivial change. It must refuse or be blocked.

Optional safety net, a local `commit-msg` git hook that rejects AI attribution:
```
#!/bin/sh
grep -qiE 'co-authored-by:.*(claude|anthropic)|generated with' "$1" && { echo "AI attribution found"; exit 1; }
exit 0
```
Save as `.git/hooks/commit-msg` and run `chmod +x .git/hooks/commit-msg`.

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

## 9. Habits that keep quality and cost down
- One task per session. `/clear` between unrelated tasks. `/context` to see what fills the window.
- Sonnet for most work, a stronger model only for design problems.
- Give Claude a way to verify its own work: tests, clippy, a reproducible command.
- Record design decisions as ADRs in docs/adr/.
- Review every dependency Claude proposes (`cargo add` is set to ask).

## 10. Learn while building
Ask Claude to explain each module after implementation, then rewrite one small function yourself.
Keep `docs/LEARNING.md` with what you learned per phase.

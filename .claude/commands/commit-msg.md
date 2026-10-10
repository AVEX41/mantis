---
description: Propose a commit message for the current changes (does not commit)
allowed-tools: Bash(git status:*), Bash(git diff:*), Bash(git log:*)
---
Inspect `git status` and `git diff` (staged and unstaged). Do NOT run git commit, add, or push.
Output only:
1. A `git add` command with the exact paths for one logical commit (suggest splitting if the diff mixes concerns).
2. A commit message in a code block: Conventional Commits subject (max 72 chars, imperative),
   blank line, body explaining why the change was made.
No Co-Authored-By line. No mention of Claude or AI.

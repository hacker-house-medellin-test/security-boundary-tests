# AGENTS.md

Owner: `hacker-house-medellin-test`
Primary product context: `hacker-house-medellin`
Tracking: `https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139`

## Semantic conflict resolution

Never force-push shared history and never resolve a conflict by wholesale selection of `ours`, `theirs`, current, or incoming. Inspect the merge base, reread every affected file completely, and examine 3–10 relevant commits from both sides when available. Include the primary organization's contracts, schemas, migrations, fixtures, CI behavior, and related repositories where they materially constrain the result.

Resolve conflicts semantically: preserve compatible intent from both sides, add or update regression tests for the reconciled behavior, scan the full tree for unresolved conflict markers, and rerun the complete deterministic suite before requesting merge. Fail closed when intent remains ambiguous.

## Repository-local Git worktrees

- Create or use a Git worktree only when the human operator explicitly authorizes it for the current task. Concurrency or a dirty checkout is not permission by itself.
- Put every authorized worktree at `<repository-root>/tmp/worktrees/<name>`; from the repository root, use `./tmp/worktrees/<name>`. Never place worktrees beside repositories or organization directories.
- Keep `tmp`, `temp`, `tmp/worktrees`, and `temp/worktrees` ignored in the repository-root `.gitignore`. Do not commit files from those directories.
- Relocate or remove a worktree only when the operator explicitly requests it. Before removal, preserve and publish intended changes, verify its commit is represented on the target branch, and confirm there are no tracked, untracked, ignored-sensitive, or in-use files that must survive. Remove it with `git worktree remove <path>` without `--force`; never delete a worktree directory with `rm`.

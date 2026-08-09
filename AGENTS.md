# AGENTS.md

Owner: `hacker-house-medellin-test`
Primary product context: `hacker-house-medellin`
Tracking: `https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139`

## Semantic conflict resolution

Never force-push shared history and never resolve a conflict by wholesale selection of `ours`, `theirs`, current, or incoming. Inspect the merge base, reread every affected file completely, and examine 3–10 relevant commits from both sides when available. Include the primary organization's contracts, schemas, migrations, fixtures, CI behavior, and related repositories where they materially constrain the result.

Resolve conflicts semantically: preserve compatible intent from both sides, add or update regression tests for the reconciled behavior, scan the full tree for unresolved conflict markers, and rerun the complete deterministic suite before requesting merge. Fail closed when intent remains ambiguous.

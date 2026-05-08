---
name: skill-sync
description: "Trigger: When updating skill metadata (metadata.scope/metadata.auto_invoke), regenerating Auto-invoke tables, or running ./skills/skill-sync/assets/sync.sh. Syncs skill metadata to AGENTS.md Auto-invoke sections."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "After creating/modifying a skill"
    - "Regenerate AGENTS.md Auto-invoke tables (sync.sh)"
    - "Troubleshoot why a skill is missing from AGENTS.md auto-invoke"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Activation Contract

Use this skill when a skill's `metadata.scope` or `metadata.auto_invoke` changes, when auto-invoke tables need regeneration, or when a skill is missing from `AGENTS.md` auto-invoke output.

## Hard Rules

- Treat `./skills/skill-sync/assets/sync.sh` as the source of truth for generated auto-invoke tables.
- Do not hand-edit generated auto-invoke sections unless the workflow itself is being fixed.
- Run `--dry-run` first when you only need verification or when metadata impact is uncertain.
- Only `metadata.scope` and `metadata.auto_invoke` should drive sync decisions.
- Keep scope values aligned to real targets: `root`, `ui`, `api`, `sdk`, `mcp_server`.

## Decision Gates

| Question | Action |
|---|---|
| Did `metadata.scope` or `metadata.auto_invoke` change? | Run `sync.sh` for real, or `--scope` if the blast radius is intentionally narrow. |
| Did only body text or examples change? | Skip sync and say why; generated tables are unaffected. |
| Are you checking expected output without modifying files? | Run `sync.sh --dry-run`. |
| Is one surface affected? | Use `sync.sh --scope <scope>`. |
| Is a skill missing from auto-invoke output? | Inspect its frontmatter first, then run `--dry-run` to confirm what the script sees. |

## Execution Steps

1. Read the changed skill frontmatter and confirm `metadata.scope` and `metadata.auto_invoke` are present and well-formed.
2. Decide whether the task needs a real sync, a dry-run, or a documented no-op.
3. If validating only, run `./skills/skill-sync/assets/sync.sh --dry-run`.
4. If updating one target, run `./skills/skill-sync/assets/sync.sh --scope <scope>`.
5. If updating all affected targets, run `./skills/skill-sync/assets/sync.sh`.
6. Verify the expected `AGENTS.md` surfaces changed only where metadata demanded it.

## Output Contract

- State whether sync was executed, dry-run only, or skipped as a no-op.
- List the scope(s) evaluated and the `AGENTS.md` file(s) affected or intentionally untouched.
- If the issue was missing auto-invoke output, explain the root cause in the skill metadata or script behavior.
- Return the exact command used for verification or update.

## References

- [Sync script](assets/sync.sh)
- [Sync script test helper](assets/sync_test.sh)
- [Repository agent rules](../../AGENTS.md)

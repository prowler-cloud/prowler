---
name: skill-sync
description: >
  Syncs skill metadata to AGENTS.md Auto-invoke sections.
  Trigger: When updating skill metadata (metadata.scope/metadata.auto_invoke), regenerating Auto-invoke tables, or running ./skills/skill-sync/assets/sync.sh (including --dry-run/--scope).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root]
  auto_invoke:
    - "After creating/modifying a skill"
    - "Regenerate AGENTS.md Auto-invoke tables (sync.sh)"
    - "Troubleshoot why a skill is missing from AGENTS.md auto-invoke"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Purpose

Keeps the Auto-invoke tables of the `AGENTS.md` files in sync with skill metadata. Run the sync script after creating a skill or changing its `metadata.scope` / `metadata.auto_invoke`.

## Required Skill Metadata

`auto_invoke` can be a single string **or** a list of actions:

```yaml
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]                              # Which AGENTS.md files

  # Option A: single action
  auto_invoke: "Creating/modifying components"

  # Option B: multiple actions
  # auto_invoke:
  #   - "Creating/modifying components"
  #   - "Refactoring component folder placement"
```

### Scope Values (only these are valid)

| Scope | Updates |
|-------|---------|
| `root` | `AGENTS.md` (repo root) |
| `ui` | `ui/AGENTS.md` |
| `api` | `api/AGENTS.md` |
| `sdk` | `prowler/AGENTS.md` |
| `mcp_server` | `mcp_server/AGENTS.md` |

- Use `sdk`, NOT `prowler`, for `prowler/AGENTS.md`. Any other value is skipped with `Warning: No AGENTS.md found for scope '<value>'`.
- `docs/AGENTS.md` has no scope: it is the docs style guide, not a skills index.
- Most skills list `root` too, so the root table is the full index of actions.

---

## What the Script Does

1. Reads every `skills/*/SKILL.md` (sorted)
2. Extracts `name`, `metadata.scope` and `metadata.auto_invoke`
3. Builds one table per scope, rows sorted by action then skill (`LC_ALL=C`)
4. Replaces the existing `## Auto-invoke Skills` (component files) or `### Auto-invoke Skills` (root) section, keeping its heading level, up to the next `---` line or H2 heading
5. If a file has no such section, inserts it after the Skills Reference blockquote (the `>` block that links `SKILL.md` files)
6. Lists skills missing `scope` or `auto_invoke`

The generated table is compact (`| Action | Skill |`). `ui/AGENTS.md` is re-aligned by the UI Prettier hook on commit, so a formatting-only diff there is expected.

It does NOT update the "Available Skills" description tables in `AGENTS.md` or `skills/README.md`: edit those by hand.

---

## Commands

```bash
# Preview (writes nothing; prints each generated table)
./skills/skill-sync/assets/sync.sh --dry-run

# Sync all AGENTS.md files
./skills/skill-sync/assets/sync.sh

# Sync one scope only
./skills/skill-sync/assets/sync.sh --scope ui

# Run the script's unit tests (temp dirs only)
bash ./skills/skill-sync/assets/sync_test.sh

# Review the result
git diff -- '*AGENTS.md'
```

---

## Checklist After Modifying Skills

- [ ] `metadata.scope` uses only `root`, `ui`, `api`, `sdk`, `mcp_server`
- [ ] `metadata.auto_invoke` describes the user action ("Creating new checks"), not the skill
- [ ] Ran `./skills/skill-sync/assets/sync.sh --dry-run` with no `Warning:` lines, then without `--dry-run`
- [ ] Reviewed `git diff -- '*AGENTS.md'` (one Auto-invoke section per file, no unrelated changes)
- [ ] Added or updated the skill row in the root `AGENTS.md` and `skills/README.md` tables

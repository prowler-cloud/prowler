---
name: skill-creator
description: >
  Creates new AI agent skills for Prowler following the Agent Skills spec and the house conventions (frontmatter, scope/auto_invoke, AGENTS.md registration).
  Trigger: When user asks to create a new skill, add agent instructions, or document patterns for AI.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root]
  auto_invoke: "Creating new skills"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Create a Skill

Create a skill when:
- A pattern is used repeatedly and AI needs guidance
- Project-specific conventions differ from generic best practices
- Complex workflows need step-by-step instructions
- Decision trees help AI choose the right approach

**Don't create a skill when:**
- Documentation already exists (create a reference instead)
- Pattern is trivial or self-explanatory
- It's a one-off task
- An existing skill covers it (extend that skill instead; check `ls skills/`)

---

## Skill Structure

```text
skills/{skill-name}/
├── SKILL.md              # Required - main skill file
├── assets/               # Optional - templates, schemas, example configs, scripts
│   ├── template.py
│   └── schema.json
└── references/           # Optional - pointers to local docs
    └── docs.md           # Points to docs/developer-guide/*.mdx
```

---

## SKILL.md Template

Full template: [assets/SKILL-TEMPLATE.md](assets/SKILL-TEMPLATE.md).

````markdown
---
name: {skill-name}
description: >
  {What this skill does, with the keywords an agent would search for}.
  Trigger: {When the AI should load this skill}.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, {component}]
  auto_invoke:
    - "{User action that must load this skill}"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## When to Use

## Critical Patterns

## Code Examples

## Commands

```bash
{Commands that validate the work}
```

## Resources
````

---

## Frontmatter Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Same as the directory name; lowercase letters, digits and single hyphens; max 64 chars |
| `description` | Yes | What + `Trigger:` sentence in one block; max 1024 chars |
| `license` | Yes | Always `Apache-2.0` for Prowler |
| `metadata.author` | Yes | `prowler-cloud` |
| `metadata.version` | Yes | Version as a quoted string (`"1.0"`); bump it on every change |
| `metadata.scope` | For auto-invoke | AGENTS.md files to list it in: `root`, `ui`, `api`, `sdk`, `mcp_server` (never `prowler`) |
| `metadata.auto_invoke` | For auto-invoke | String or list of user actions ("Creating new checks") |
| `allowed-tools` | Recommended | Tools the skill needs |

`scope` and `auto_invoke` feed `skills/skill-sync/assets/sync.sh` (see `skill-sync`).

---

## Naming Conventions

| Type | Pattern | Examples |
|------|---------|----------|
| Generic skill | `{technology}` | `pytest`, `playwright`, `typescript` |
| Prowler-specific | `prowler-{component}` | `prowler-api`, `prowler-ui`, `prowler-sdk-check` |
| Testing skill | `prowler-test-{component}` | `prowler-test-sdk`, `prowler-test-api`, `prowler-test-mcp` |
| Workflow skill | `{action}-{target}` or `{target}-{action}` | `skill-creator`, `skill-sync` |

---

## Decision: assets/ vs references/

```text
Need code templates?        → assets/
Need JSON schemas?          → assets/
Need example configs?       → assets/
Need a runnable script?     → assets/ (with a test next to it, e.g. skill-sync/assets/sync_test.sh)
Link to existing docs?      → references/
Link to external guides?    → references/ (with local path when one exists)
```

**Key Rule**: `references/` should point to LOCAL files (`docs/developer-guide/*.mdx`, `docs/AGENTS.md`), not web URLs, unless the tool's docs only exist externally (e.g. `gh-aw`).

---

## Decision: Prowler-Specific vs Generic

```text
Patterns apply to ANY project?     → Generic skill (e.g., pytest, typescript)
Patterns are Prowler-specific?     → prowler-{name} skill
Generic skill needs Prowler info?  → Add references/ pointing to Prowler docs
```

---

## Content Guidelines

### DO
- Start with the most critical patterns (ALWAYS/NEVER rules)
- Verify every path, class, command and version against the current code before writing it
- Use tables for decision trees
- Keep code examples minimal and copied from real code
- Include a Commands section with copy-paste commands that validate the work
- Keep `SKILL.md` under 500 lines; move long material to `assets/` or `references/`

### DON'T
- Add Keywords section (agent searches frontmatter, not body)
- Duplicate content from existing docs or templates (reference the file instead; copies go stale)
- Include lengthy explanations (link to docs)
- Add troubleshooting sections (keep focused)
- Hardcode versions that live in lock files unless the skill is about that version

---

## Registering the Skill

1. Run the sync script to generate the Auto-invoke rows:
   ```bash
   ./skills/skill-sync/assets/sync.sh --dry-run   # check for "Warning:" lines
   ./skills/skill-sync/assets/sync.sh
   ```
2. Add a row to the matching "Available Skills" table in the root `AGENTS.md` (not generated):
   ```markdown
   | `{skill-name}` | {Description} | [SKILL.md](skills/{skill-name}/SKILL.md) |
   ```
3. Add a row to the matching table in `skills/README.md`.
4. If a component `AGENTS.md` should point to it, add it to that file's Skills Reference blockquote.

---

## Checklist Before Creating

- [ ] Skill doesn't already exist (check `skills/`)
- [ ] Pattern is reusable (not one-off)
- [ ] Name follows conventions and matches the directory
- [ ] Frontmatter is complete (description includes `Trigger:`; scope values are valid)
- [ ] Every concrete claim verified against the code
- [ ] Critical patterns are clear; code examples are minimal
- [ ] Commands section exists
- [ ] `sync.sh` run; root `AGENTS.md` and `skills/README.md` tables updated

## Resources

- **Templates**: See [assets/SKILL-TEMPLATE.md](assets/SKILL-TEMPLATE.md)
- **Spec**: https://agentskills.io/specification
